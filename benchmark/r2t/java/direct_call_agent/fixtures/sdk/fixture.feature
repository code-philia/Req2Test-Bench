Feature: r2t direct-call SDK fixture

  Scenario: the retained helpers and a Mockito answer reach production
    Given the fixture has an address
    When the fixture fetches a mocked base64 block "v2algodclient_responsejsons/block-header.base64"
    Then a Mockito answer constructs an address and so does the step
