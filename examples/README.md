# Examples

This folder is intentionally empty of generated credentials/keys in
the git repo (private keys and keystores should never be committed).

To populate it with real working examples, run the Quick Start
commands from the main README:

```bash
python -m src.ca init
python -m src.issue_cert --name "Dr. Alice Sharma" --org "EduSign University" --out alice
python -m src.sign --keystore keystore/alice.p12 --student "Jon Doe" \
    --degree "BSc Computer Science" --institution "EduSign University" \
    --out examples/jon_doe_degree.json
python -m src.verify --credential examples/jon_doe_degree.json
```
