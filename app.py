import streamlit as st

import analyzer
import custody
import metadata
import report
import vault

st.set_page_config(page_title="Digital Evidence Vault", page_icon="🔒", layout="wide")
st.title("🔒 Digital Evidence Vault")
st.caption(
    "Investigation-support prototype. Analysis results are advisory indicators, "
    "not final legal proof."
)

# ---------- Who is working? (needed for chain of custody) ----------
actor = st.sidebar.text_input("Investigator name", key="actor").strip()
st.sidebar.caption("Every action is recorded in the custody ledger under this name.")
if not actor:
    st.info("Enter your name in the sidebar on the left to begin.")
    st.stop()

# ---------- 1. Add evidence ----------
st.header("1. Add evidence")
upload = st.file_uploader(
    "Upload an image", type=["jpg", "jpeg", "png", "tif", "tiff", "bmp", "webp"]
)

if upload is not None:
    data = upload.getvalue()  # raw bytes exactly as uploaded
    st.write(f"**File:** {upload.name} ({len(data):,} bytes)")
    st.write("**SHA-256 (computed before storing):**")
    st.code(vault.sha256_bytes(data))

    if st.button("Save to vault"):
        try:
            record, is_new = vault.ingest(data, upload.name)
            if is_new:
                custody.log_event(
                    record["id"], "INGESTED", actor,
                    f"file={record['original_name']}; sha256={record['sha256']}",
                )
                st.success(f"Saved as Evidence #{record['id']} (read-only).")
            else:
                custody.log_event(
                    record["id"], "DUPLICATE_UPLOAD", actor,
                    f"file={upload.name}; already stored, nothing changed",
                )
                st.warning(
                    f"This exact file is already in the vault as Evidence #{record['id']}. "
                    "Nothing was changed."
                )
        except ValueError as err:
            st.error(str(err))

# ---------- 2. Vault contents ----------
st.header("2. Vault contents")
rows = vault.list_evidence()

if not rows:
    st.info("The vault is empty. Upload an image above to add the first item.")
else:
    st.dataframe(
        [
            {
                "ID": r["id"],
                "Original name": r["original_name"],
                "SHA-256": r["sha256"],
                "Size (bytes)": r["size_bytes"],
                "Stored (UTC)": r["ingested_at"],
            }
            for r in rows
        ]
    )

    st.subheader("Verify integrity")
    pick = st.selectbox("Choose evidence ID", [r["id"] for r in rows], key="verify_pick")
    if st.button("Verify now"):
        intact, current, recorded = vault.verify(pick)
        custody.log_event(
            pick, "INTEGRITY_CHECK", actor, "result=" + ("INTACT" if intact else "FAILED")
        )
        if intact:
            st.success("INTACT: the stored file matches its recorded hash.")
        else:
            st.error("TAMPERED OR MISSING: the stored file no longer matches its recorded hash.")
        st.write("Recorded hash:")
        st.code(recorded)
        st.write("Hash now:")
        st.code(current)

    # ---------- 3. Metadata ----------
    st.header("3. Metadata (EXIF)")
    meta_id = st.selectbox("Choose evidence ID", [r["id"] for r in rows], key="meta_pick")
    rec = next(r for r in rows if r["id"] == meta_id)

    intact, _, _ = vault.verify(meta_id)
    if not intact:
        st.error("This file failed its integrity check, so metadata is not shown.")
    else:
        try:
            result = metadata.extract(rec["stored_path"])
        except Exception as err:
            st.error(f"Could not read this image: {err}")
        else:
            # log once per selection, not on every page refresh
            if st.session_state.get("last_meta_logged") != (meta_id, actor):
                custody.log_event(meta_id, "METADATA_VIEWED", actor, "EXIF extracted (read-only)")
                st.session_state["last_meta_logged"] = (meta_id, actor)

            left, right = st.columns([1, 2])
            with left:
                st.image(rec["stored_path"], caption=rec["original_name"])
            with right:
                st.subheader("Observations (advisory)")
                for note in result["observations"]:
                    st.info(note)
                st.subheader("Basic file information")
                st.table({k: [v] for k, v in result["basic"].items()})

            if result["gps"]:
                g = result["gps"]
                st.subheader("GPS location")
                st.write(f"Latitude {g['latitude']}, Longitude {g['longitude']}")
                st.markdown(f"[Open in map]({g['map_url']})")

            st.subheader("All EXIF fields")
            if result["exif"]:
                st.dataframe(
                    [{"Field": k, "Value": v} for k, v in result["exif"].items()]
                )
            else:
                st.write("No EXIF fields found.")

# ---------- 4. Chain of custody ----------
st.header("4. Chain-of-custody ledger")
ok, message, count, head = custody.verify_chain()
if count == 0:
    st.info("No custody entries yet. They appear automatically as you work.")
else:
    if ok:
        st.success(f"{message} ({count} entries)")
    else:
        st.error(f"LEDGER TAMPERING DETECTED. {message}")
    st.write("Latest chain hash (note this down or email it to yourself as an outside record):")
    st.code(head)

    ids = ["All evidence"] + [r["id"] for r in rows]
    show = st.selectbox("Show entries for", ids, key="ledger_filter")
    entries = custody.get_log(None if show == "All evidence" else show)
    st.dataframe(
        [
            {
                "Entry": e["id"],
                "Evidence": e["evidence_id"],
                "Action": e["action"],
                "Who": e["actor"],
                "When (UTC)": e["timestamp"],
                "Details": e["details"],
                "Entry hash": e["entry_hash"][:16] + "…",
            }
            for e in entries
        ]
    )

# ---------- 5. Forensic analysis (advisory) ----------
st.header("5. Image forensic analysis (advisory)")
st.warning(
    "Error Level Analysis (ELA) and the risk score are advisory indicators to guide "
    "a human investigator. They are not proof that an image is genuine or fake."
)

if not rows:
    st.info("Add evidence first.")
else:
    an_id = st.selectbox("Choose evidence ID", [r["id"] for r in rows], key="an_pick")
    arec = next(r for r in rows if r["id"] == an_id)
    a_intact, _, _ = vault.verify(an_id)
    if not a_intact:
        st.error("This file failed its integrity check, so analysis is not run.")
    else:
        try:
            a_meta = metadata.extract(arec["stored_path"])
            res = analyzer.analyze(arec["stored_path"], a_meta["exif"])
        except Exception as err:
            st.error(f"Could not analyse this image: {err}")
        else:
            import os
            os.makedirs("reports", exist_ok=True)
            res["ela_image"].save(os.path.join("reports", f"ela_{an_id}.png"))
            if st.session_state.get("last_an_logged") != (an_id, actor):
                custody.log_event(
                    an_id, "ELA_ANALYSIS", actor,
                    f"advisory score={res['score']}/100 ({res['level']}); original not modified",
                )
                st.session_state["last_an_logged"] = (an_id, actor)

            c1, c2 = st.columns(2)
            with c1:
                st.image(arec["stored_path"], caption="Original (unchanged)")
            with c2:
                st.image(res["ela_image"], caption="ELA map (derived copy)")

            st.metric("Advisory risk score", f"{res['score']} / 100", res["level"] + " indicator", delta_color="off")
            st.progress(res["score"] / 100)

            st.subheader("What contributed to the score")
            if res["factors"]:
                st.table({
                    "Factor": [f for f, _ in res["factors"]],
                    "Points": [p for _, p in res["factors"]],
                })
            else:
                st.write("No factors added points.")

            st.subheader("How to read the ELA map")
            st.write(
                "Even brightness means the whole image has a similar compression history. "
                "A bright patch with a different texture from its surroundings deserves a "
                "closer look. Edges and fine detail are naturally bright."
            )
            st.subheader("Limitations of this analysis")
            for item in res["limits"]:
                st.write("• " + item)

# ---------- 6. PDF report ----------
st.header("6. PDF report")
if not rows:
    st.info("Add evidence first.")
else:
    rp_id = st.selectbox("Choose evidence ID", [r["id"] for r in rows], key="rp_pick")
    rrec = next(r for r in rows if r["id"] == rp_id)

    if st.button("Generate PDF report"):
        import os
        from datetime import datetime, timezone
        r_intact, _, _ = vault.verify(rp_id)
        try:
            r_meta = metadata.extract(rrec["stored_path"])
            r_an = analyzer.analyze(rrec["stored_path"], r_meta["exif"])
            custody.log_event(rp_id, "REPORT_GENERATED", actor, "PDF report compiled")
            c_ok, c_msg, _, c_head = custody.verify_chain()
            os.makedirs("reports", exist_ok=True)
            stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            path = os.path.join("reports", f"report_EV{rp_id}_{stamp}.pdf")
            report.build_report(
                path, evidence=rrec, actor=actor, integrity_ok=r_intact, meta=r_meta,
                analysis=r_an, custody_entries=list(reversed(custody.get_log(rp_id))),
                chain_ok=c_ok, chain_message=c_msg, chain_head=c_head,
            )
            pdf_hash = vault.sha256_file(path)
            custody.log_event(rp_id, "REPORT_FILE_HASHED", actor, f"file={os.path.basename(path)}; sha256={pdf_hash}")
            st.session_state["report_info"] = {"id": rp_id, "path": path, "sha": pdf_hash}
        except Exception as err:
            st.error(f"Could not build the report: {err}")

    info = st.session_state.get("report_info")
    if info and info["id"] == rp_id:
        st.success(f"Report saved: {info['path']}")
        st.write("SHA-256 of this report file (keep it with the report):")
        st.code(info["sha"])
        with open(info["path"], "rb") as f:
            st.download_button("Download PDF", f.read(), file_name=info["path"].replace("\\", "/").split("/")[-1], mime="application/pdf")
