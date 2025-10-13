from b9phish.parse import parse_authentication_results


def test_parse_auth_results_basic():
    ar = "mx.google.com; spf=fail (google.com: domain of spoofed.com does not designate 1.2.3.4 as permitted sender) smtp.mailfrom=spoofed.com; dkim=none; dmarc=none"
    res = parse_authentication_results(ar)
    assert res["spf"] == "fail"
    assert res["dkim"] == "none"
    assert res["dmarc"] == "none"
