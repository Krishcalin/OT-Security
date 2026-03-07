# Contributing

## Adding Checks
1. Identify the module (identity_access, core_modules, extended_modules)
2. Add a `check_*` method to the appropriate auditor class
3. Add sample data demonstrating the issue in generate_sample_data.py
4. Run: `python ariba_scanner.py --data-dir ./sample_data`
5. Update README check count and submit PR

## Adding New Data Sources
1. Add filename mapping to FILE_MAP in modules/base.py
2. Create sample export in generate_sample_data.py
3. Reference via `self.data.get("key_name")` in auditor checks

## Code Style
- Python 3.8+, zero external dependencies
- Every finding must include: check_id, remediation, and references
