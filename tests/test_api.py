from application import application
import base64


def test_gettoken():
    """Test that a user is authenticated and response is 200 ok"""
    client = application.test_client()

    credentials = base64.b64encode(b"Yoda:theforce").decode("utf-8")

    res = client.get("/gettoken", headers={"Authorization": f"Basic {credentials}"})
    print(res)
    assert res.status_code == 200
