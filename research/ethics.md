# Research Data Ethics

## Data Collection Guidelines

All data in this repository must comply with the following:

1. **Explicit Consent** - Only capture data from networks you own or have written authorization to monitor
2. **Anonymization** - Remove or hash all PII before publishing:
   - MAC addresses → Randomize or hash
   - SSIDs → Remove or replace with synthetic names
   - GPS coordinates → Reduce precision or remove
   - Timestamps → Keep for temporal analysis but remove date if possible
3. **Minimal Collection** - Only collect data necessary for research

## Published Data Requirements

Before adding pcaps or datasets to this repository:

- [ ] All MAC addresses randomized/hashed
- [ ] No real SSIDs containing personal information
- [ ] No GPS coordinates with fine precision
- [ ] Ethics approval obtained (if for academic research)
- [ ] Data collection consent documented
- [ ] License clearly specified

## Licensing

Research data in this directory is released under CC0-1.0 unless otherwise noted.

## For Academic Use

If using this data for academic research:

1. Obtain IRB approval if required by your institution
2. Cite appropriately
3. Document any transformations made to the data
4. Consider privacy implications in your publications

## Contact

For questions about data ethics: security@example.com
