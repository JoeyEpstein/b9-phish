from b9phish.features import extract_urls, url_heuristics

def test_url_extract_and_heuristics():
    txt = "Click https://login.example.zip/reset and https://microsoft-support-verify.example.com now"
    urls = extract_urls(txt)
    assert len(urls) == 2
    sigs = [url_heuristics(u) for u in urls]
    assert any(s["suspicious_tld"] for s in sigs)
    assert any(s["deceptive_keywords"] for s in sigs)
