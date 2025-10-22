# Cisco Firepower Tools

This repository contains Python-based utilities for interacting with and automating tasks in **Cisco Firepower Management Center (FMC)**.  
Each script performs a specific function such as exporting policies, auditing logging configurations, or cleaning up unused objects.

---

## Repository Structure

Firepower/
├── common/ # Shared libraries and helper functions (e.g., FMC login, API calls)
├── data/ # Input data files (e.g., CSVs for object creation or mapping)
├── fmc_config/ # Configuration parameters (e.g., base_url, credentials, domain UUID)
├── output/ # Generated output from scripts (e.g., CSV, JSON, Excel reports)
├── scripts/ # Individual tools for performing FMC operations
├── .gitignore
├── pyproject.toml
└── README.md

## Running Scrips

Each tool is in the scripts/ directory and can be executed directly from the project root.
For example:
python scripts/fmc_inventory.py
python scripts/fmc_logging_audit.py

## Notes:

Requires Python 3.10+
Designed for Cisco FMC 7.x / API v1.x
SSL warnings are suppressed automatically (urllib3.disable_warnings()) for convenience.
