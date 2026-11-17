## RAVEN Sanity Check Trace Release

This directory is a public-facing release package for the dynamic execution traces used to sanity-check whether RAVEN-generated PE variants preserved the runtime behavior of their corresponding originals.

The release contains all 62 original/variant pairs used in the sanity check.

### Directory Layout

```text
sanity_check/
├── README.md
├── trace_manifest.csv
├── original/
├── variant/
└── scripts/
```

### Trace Format

Each trace is a tab-separated event log with the header:

```text
# event_id    type    name    args
```

The event-type letters are inferred from the log schema:

- `T`: trace-level marker, such as the initial `entry`
- `A`: API or function-level event
- `S`: system-call event
- `E`: terminal exit record

### What Is Included

- 62 included original/variant pairs
- Dynamic execution traces only
- No malware binaries
- SHA-256-based sample identifiers derived from filenames

### Export Note

For one source trace, non-record trailing NUL padding after the final valid event was omitted during public export. No execution-event record was removed or modified.

### Manifest Columns

`trace_manifest.csv` contains:

- `sha256`: sample identifier
- `family`: malware family label encoded in the filename
- `operator`: PE transformation applied to the variant
- `original_trace`: relative path to the released original trace
- `variant_trace`: relative path to the released variant trace
- `status`: inclusion status in the public package
- `notes`: release notes for padding-handled or otherwise notable cases
- `original_lines`, `variant_lines`: line counts measured from the public release files
- `original_bytes`, `variant_bytes`: byte sizes measured from the public release files

### Pairing And Comparison

Pairs are matched by SHA-256 extracted from the filenames. Variants are additionally labeled by the transformation operator suffix in the variant filename.

Trace comparison is performed over valid TSV event records using the `type` and `name` fields, while argument values and non-record trailing padding are ignored. All 62 pairs preserve the same core event sequence; 61 are exact matches, and one differs only in the presence of the final exit record.

The companion scripts in `scripts/` provide:

- `summarize_traces.py`: manifest validation and event-sequence comparison
- `export_valid_tsv_records.py`: export helper that retains only valid TSV event records from a source trace file

Run:

```bash
python3 scripts/summarize_traces.py
```

Expected result for this release:

```text
manifest_rows,62
status,included,62
included_pairs,62
missing_files,0
content_mismatches,0
exact_event_sequence_matches,61
terminal_record_only_differences,1
event_sequence_differences,0
```

### Timing And Environment Notes

This directory preserves the trace files themselves, but it does not preserve a full machine-readable execution-environment description.

- The logs clearly reflect Windows user-mode execution activity, including `ntdll.dll` API and syscall-related events.
- Filesystem timestamps in the source snapshot range from `2026-05-28 21:26:43` to `2026-05-28 23:24:24`.
- Those timestamps should be treated as snapshot file times, not as a fully authoritative provenance record for the original sandbox runs.

If you need stronger provenance for publication, add the exact sandbox or VM configuration, OS version, tracing tool version, and collection command line from the experiment notebook or lab records before final submission.
