Feature: preserve setup and action while stripping native Then bodies
  Scenario: native selected handlers
    Given a preserved setup
    When a preserved action
    Then a method assertion
    And a deliberately false literal assertion
