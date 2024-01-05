# GuardScope Analyzer

GuardScope Analyzer is a tool designed to analyze and monitor the usage of IP sets and regular expression pattern sets in Web Application Firewalls (WAFs) and rule groups.

## Features

- **IP Set Analysis:** Easily inspect and understand the IPSets configured in your WAFs or RuleGroups.
- **Regex Pattern Set Examination:** Analyze the regular expression pattern sets employed for security filtering.

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/daknhh/waf-tools.git
   ````
2. Navigate to the project directory:
    ```bash
    cd GuardScopeAnalyzer
    ````

3. Install dependencies:
    ```bash
    pip install -r requirements.txt
    ````

### Usage
    Run the GuardScope Analyzer:

    ```bash
    python guardscope_analyzer.py -h
    ````

Follow the on-screen instructions to input the necessary information, such as WAF configuration file paths and rule group details.

Analyze the generated reports for valuable insights into your WAF's IP sets and regex pattern sets.

### Contribution
Contributions are welcome! If you find any issues or have suggestions for improvements, please create a GitHub issue or submit a pull request.