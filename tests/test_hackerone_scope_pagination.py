"""Regression test for a real bug found live against intigriti:watsons'
sibling investigation: HackerOne's structured_scopes fetch had no
pagination loop, unlike fetch_programs. Confirmed live against the real
API (2026-09-17): estee-lauder, cbre, mars, visa, aon, pepsico_vdp,
oppo_bbp and ferrero were all stuck at exactly 100 in-scope assets in
the state db -- the page size limit, not their actual scope. Re-fetching
visa with the pagination fix returned 169 real in-scope assets."""
import httpx

from bbhunter.discovery.hackerone import HackerOneConnector


def _scope_item(n: int) -> dict:
    return {
        "attributes": {
            "asset_identifier": f"host{n}.example.com",
            "asset_type": "URL",
            "eligible_for_submission": True,
        }
    }


def test_structured_scopes_follows_pagination_past_first_page():
    page_1_items = [_scope_item(i) for i in range(100)]
    page_2_items = [_scope_item(i) for i in range(100, 130)]

    def handler(request: httpx.Request) -> httpx.Response:
        if "/hackers/programs/testprog/structured_scopes" in str(request.url):
            page_number = request.url.params.get("page[number]", "1")
            if page_number == "1":
                return httpx.Response(
                    200,
                    json={"data": page_1_items, "links": {"next": "...page=2..."}},
                )
            elif page_number == "2":
                return httpx.Response(200, json={"data": page_2_items, "links": {}})
            return httpx.Response(200, json={"data": [], "links": {}})
        return httpx.Response(404, json={})

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="https://api.hackerone.com/v1")
    connector = HackerOneConnector()
    program = connector._to_program(
        client,
        {"attributes": {"handle": "testprog", "name": "Test Program", "policy": "", "offers_bounties": True}},
    )
    client.close()

    assert program is not None
    assert len(program.in_scope) == 130


def test_structured_scopes_stops_when_no_next_link():
    page_items = [_scope_item(i) for i in range(5)]
    call_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        return httpx.Response(200, json={"data": page_items, "links": {}})

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="https://api.hackerone.com/v1")
    connector = HackerOneConnector()
    program = connector._to_program(
        client,
        {"attributes": {"handle": "testprog", "name": "Test Program", "policy": "", "offers_bounties": True}},
    )
    client.close()

    assert len(program.in_scope) == 5
    assert call_count == 1  # must not keep paging forever when there's no "next" link
