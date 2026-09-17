# Real datasets (place your CIC-IDS CSV files here)

This directory is where you drop **real** labelled network-flow datasets for
evaluation. The application ships with **no** synthetic attack data here on
purpose — real validation must use real data.

## Primary dataset — CSE-CIC-IDS2018
- Source: Canadian Institute for Cybersecurity (CIC), University of New Brunswick.
- https://www.unb.ca/cic/datasets/ids-2018.html (also mirrored on AWS Open Data).
- Format: CICFlowMeter CSV, one network flow per row, with a `Label` column
  (`Benign` vs attack name, e.g. `DDoS`, `Bruteforce`, `Infiltration`, `Bot`).

## Secondary validation dataset — CIC-IDS2017
- https://www.unb.ca/cic/datasets/ids-2017.html
- Same CICFlowMeter format; the 2017 "GeneratedLabelledFlows" also include
  `Source IP` / `Destination IP` columns (2018 processed CSVs often omit IPs).

## How the app uses these files
1. Configure the location (optional) with `DATASET_DIR` (defaults to this folder).
2. In the app, open **Real Data** → upload a CIC-IDS CSV (or use the Evaluation
   page). The ingestion layer maps CICFlowMeter columns to the internal schema:

   | CIC column | Internal field |
   |------------|----------------|
   | `Timestamp` | `timestamp` |
   | `Source IP` / `Src IP` | `source_ip` |
   | `Destination IP` / `Dst IP` | `destination_ip` |
   | `Destination Port` / `Dst Port` | `port` |
   | `Protocol` | `protocol` |
   | `TotLen Fwd Pkts` / `Total Length of Fwd Packets` | `bytes` |
   | `Label` | `label` (ground truth — used ONLY for evaluation) |

3. Detection runs on the flow features (it never reads `label`). The
   **Evaluation** page then compares detections against the `Label` ground
   truth to compute precision / recall / F1 / false-positive rate.

## Important
- The original rows are never modified; normalized events are stored separately.
- `label` is ground truth for scoring only. It is **not** used to fabricate
  detections or findings.
- Files here are git-ignored (they are large); they are not committed.
