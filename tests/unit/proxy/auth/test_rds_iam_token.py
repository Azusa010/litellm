from io import BytesIO
from typing import Final
from urllib.parse import parse_qs, unquote, urlsplit

import boto3
import pytest
from botocore.awsrequest import AWSPreparedRequest, AWSResponse
from urllib3.response import HTTPResponse

from litellm.proxy.auth.rds_iam_token import generate_iam_auth_token, init_rds_client


@pytest.mark.parametrize(
    ("db_host", "expected_region"),
    [
        ("w.abc123.us-east-1.rds.amazonaws.com", "us-east-1"),
        ("lit-r.abc123xyz.ap-northeast-1.rds.amazonaws.com", "ap-northeast-1"),
        ("c.cluster-abc123.eu-central-1.rds.amazonaws.com", "eu-central-1"),
        ("c.cluster-ro-abc.eu-west-2.rds.amazonaws.com", "eu-west-2"),
        ("p.proxy-abc123.us-west-2.rds.amazonaws.com", "us-west-2"),
        ("ep1.endpoint.proxy-ab0cd1efghij.us-east-2.rds.amazonaws.com", "us-east-2"),
        ("d.abc123.cn-north-1.rds.amazonaws.com.cn", "cn-north-1"),
        ("d.abc123.us-gov-west-1.rds.amazonaws.com", "us-gov-west-1"),
        ("W.ABC123.US-EAST-1.RDS.AMAZONAWS.COM", "us-east-1"),
        ("lit.abc.us-east-1.rds.amazonaws.com.", "us-east-1"),
        ("writer.aurora.local", "ap-northeast-1"),
        ("db.internal.example.com", "ap-northeast-1"),
        ("10.0.0.5", "ap-northeast-1"),
        ("localhost", "ap-northeast-1"),
        ("us-east-1.rds.amazonaws.com.evil.example", "ap-northeast-1"),
    ],
)
def test_generate_iam_auth_token_signs_for_the_database_hostname_region(
    db_host: str, expected_region: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    monkeypatch.delenv("AWS_DEFAULT_PROFILE", raising=False)
    client: Final = boto3.client(
        "rds",
        region_name="ap-northeast-1",
        aws_access_key_id="AKIDEXAMPLE",
        aws_secret_access_key="x" * 40,
    )

    token: Final = unquote(
        generate_iam_auth_token(
            db_host=db_host,
            db_port="5432",
            db_user="litellm",
            client=client,
        )
    )
    credential: Final = parse_qs(urlsplit(token).query)["X-Amz-Credential"][0]

    assert token.split("?", maxsplit=1)[0] == f"{db_host}:5432/"
    assert credential.split("/")[2] == expected_region


@pytest.mark.parametrize("assume_role", [False, True])
@pytest.mark.parametrize("session_token", [None, "temporary/session+token=="])
def test_environment_credentials_retain_session_token_when_signing(
    assume_role: bool, session_token: str | None, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in (
        "AWS_PROFILE",
        "AWS_DEFAULT_PROFILE",
        "AWS_PROFILE_NAME",
        "AWS_ROLE_NAME",
        "AWS_ROLE_ARN",
        "AWS_SESSION_NAME",
        "AWS_WEB_IDENTITY_TOKEN",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AWS_SESSION_TOKEN",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AWS_REGION_NAME", "us-east-1")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIDEXAMPLE")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "x" * 40)
    if session_token is not None:
        monkeypatch.setenv("AWS_SESSION_TOKEN", session_token)
    if assume_role:
        monkeypatch.setenv("AWS_ROLE_NAME", "arn:aws:iam::123456789012:role/database")
        monkeypatch.setenv("AWS_SESSION_NAME", "database-iam-auth")
    session: Final = boto3.Session(region_name="us-east-1")
    monkeypatch.setattr(boto3, "DEFAULT_SESSION", session)

    def assume_role_response(request: AWSPreparedRequest, **kwargs: object) -> AWSResponse:
        assert request.headers.get("X-Amz-Security-Token") == (
            session_token.encode() if session_token is not None else None
        )
        assert b"Credential=AKIDEXAMPLE/" in request.headers["Authorization"]
        payload: Final = b"""<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
          <AssumeRoleResult><Credentials>
            <AccessKeyId>ASIAASSUMED</AccessKeyId><SecretAccessKey>assumed-secret</SecretAccessKey>
            <SessionToken>assumed/session+token==</SessionToken>
          </Credentials></AssumeRoleResult>
        </AssumeRoleResponse>"""
        return AWSResponse(request.url, 200, {}, HTTPResponse(body=BytesIO(payload), preload_content=False))

    session.events.register("before-send.sts.AssumeRole", assume_role_response)
    token: Final = generate_iam_auth_token("db.example.com", "5432", "litellm")
    query: Final = parse_qs(urlsplit(unquote(token)).query)
    expected_token: Final = "assumed/session+token==" if assume_role else session_token

    assert query.get("X-Amz-Security-Token") == ([expected_token] if expected_token is not None else None)
    assert query["X-Amz-Credential"][0].split("/")[0] == ("ASIAASSUMED" if assume_role else "AKIDEXAMPLE")
    assert query["DBUser"] == ["litellm"]


@pytest.mark.parametrize("explicit_credentials", [False, True])
def test_explicit_credentials_take_precedence_over_the_default_chain(
    explicit_credentials: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    session: Final = boto3.Session(
        aws_access_key_id="DEFAULTKEY", aws_secret_access_key="default-secret", aws_session_token="default-token"
    )
    monkeypatch.setattr(boto3, "DEFAULT_SESSION", session)
    client: Final = init_rds_client(
        aws_region_name="us-east-1",
        aws_access_key_id="EXPLICITKEY" if explicit_credentials else None,
        aws_secret_access_key="explicit-secret" if explicit_credentials else None,
        aws_session_token="explicit-token" if explicit_credentials else None,
    )
    token: Final = generate_iam_auth_token("db.example.com", "5432", "litellm", client=client)
    query: Final = parse_qs(urlsplit(unquote(token)).query)

    assert query["X-Amz-Security-Token"] == (["explicit-token"] if explicit_credentials else ["default-token"])
    assert query["X-Amz-Credential"][0].split("/")[0] == ("EXPLICITKEY" if explicit_credentials else "DEFAULTKEY")
