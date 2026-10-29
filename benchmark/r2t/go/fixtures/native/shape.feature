@selected
Feature: Qualified wrapper and registry shapes
  Background:
    Given a retained background helper

  Scenario Outline: Typed value <value>
    Given the probe value is <value>
    And the probe table:
      | key    | value |
      | answer | 42    |
    And the probe docstring:
      """
      alpha
      beta
      """
    Then the probe value equals <value>

    Examples: First
      | value |
      | 1     |
      | 2     |

    Examples: Second
      | value |
      | 3     |
      | 4     |
