"""Ingesta de CERT r4.2: de logs crudos a una rejilla usuario x día.

Salidas en processed_dir:
    features.parquet   conteos diarios por usuario y señal (sin etiquetas)
    users.parquet      rol, unidad, departamento, grupo de pares y último día activo
    calendar.parquet   día, fin de semana y festivo detectado
    labels.parquet     answer key a nivel usuario-día (solo se abre para evaluar)
    incidents.parquet  un registro por incidente del answer key
    ingest_log.json    cifras de control de la ingesta

Las etiquetas quedan en archivos aparte: los detectores se construyen sin mirarlas.
"""
from __future__ import annotations

import glob
import json
import os

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.csv as pacsv

DATE_FMT = "%m/%d/%Y %H:%M:%S"


FILAS: dict[str, int] = {}   # eventos leídos por archivo (cifra de control: se guarda en ingest_log.json)


def _stream(path: str, cols: list[str]):
    """Lee un CSV grande por bloques con pyarrow, solo con las columnas pedidas."""
    ro = pacsv.ReadOptions(block_size=64 << 20)
    po = pacsv.ParseOptions(quote_char=False)
    co = pacsv.ConvertOptions(include_columns=cols, column_types={c: pa.string() for c in cols})
    for batch in pacsv.open_csv(path, read_options=ro, parse_options=po, convert_options=co):
        FILAS[os.path.basename(path)] = FILAS.get(os.path.basename(path), 0) + batch.num_rows
        ts = pc.strptime(batch.column("date"), format=DATE_FMT, unit="s")
        df = batch.drop_columns(["date"]).to_pandas()
        df["date"] = ts.to_pandas()
        df["day"] = df["date"].dt.normalize()
        df["hour"] = df["date"].dt.hour
        yield df


def _sum_parts(parts: list[pd.DataFrame]) -> pd.DataFrame:
    """Un mismo usuario-día puede quedar en dos bloques: se vuelve a sumar."""
    df = pd.concat(parts)
    return df.groupby(["user", "day"]).sum()


def calendar(logon_path: str, start: str, end: str, holiday_ratio: float) -> pd.DataFrame:
    """Fines de semana y festivos. Festivo = día hábil con muy pocos logons en toda la organización."""
    n = []
    for df in _stream(logon_path, ["date", "user", "activity"]):
        n.append(df.loc[df["activity"] == "Logon"].groupby("day").size())
    per_day = pd.concat(n).groupby(level=0).sum()
    days = pd.date_range(start, end, freq="D")
    per_day = per_day.reindex(days, fill_value=0)
    cal = pd.DataFrame({"day": days, "org_logons": per_day.to_numpy()})
    cal["weekend"] = cal["day"].dt.dayofweek >= 5
    med = cal.loc[~cal["weekend"], "org_logons"].median()
    cal["holiday"] = (~cal["weekend"]) & (cal["org_logons"] < holiday_ratio * med)
    cal["off_day"] = cal["weekend"] | cal["holiday"]
    return cal


def _after_hours(df: pd.DataFrame, off_days: set, ws: int, we: int) -> pd.Series:
    return df["day"].isin(off_days) | (df["hour"] < ws) | (df["hour"] >= we)


def aggregate(raw_dir: str, cal: pd.DataFrame, ws: int, we: int) -> tuple[pd.DataFrame, pd.Series, dict]:
    off = set(cal.loc[cal["off_day"], "day"])
    log = {}

    # logon.csv: logons, logons fuera de horario, equipos distintos y último día con actividad
    parts, pcs, last = [], [], []
    for df in _stream(os.path.join(raw_dir, "logon.csv"), ["date", "user", "pc", "activity"]):
        last.append(df.groupby("user")["day"].max())
        lg = df[df["activity"] == "Logon"].copy()
        lg["logons"] = 1
        lg["after_hours_logons"] = _after_hours(lg, off, ws, we).astype(int)
        parts.append(lg.groupby(["user", "day"])[["logons", "after_hours_logons"]].sum())
        pcs.append(lg[["user", "day", "pc"]].drop_duplicates())
    logon = _sum_parts([p.reset_index() for p in parts])
    unique_pcs = pd.concat(pcs).drop_duplicates().groupby(["user", "day"]).size().rename("unique_pcs")
    last_active = pd.concat(last).groupby(level=0).max()

    # device.csv: conexiones USB y conexiones fuera de horario
    parts = []
    for df in _stream(os.path.join(raw_dir, "device.csv"), ["date", "user", "activity"]):
        d = df[df["activity"] == "Connect"].copy()
        d["usb_events"] = 1
        d["after_hours_usb"] = _after_hours(d, off, ws, we).astype(int)
        parts.append(d.groupby(["user", "day"])[["usb_events", "after_hours_usb"]].sum().reset_index())
    device = _sum_parts(parts)

    # file.csv: cada registro es una copia de archivo a un medio removible (readme de r4.2)
    parts = [df.groupby(["user", "day"]).size().rename("file_events").reset_index()
             for df in _stream(os.path.join(raw_dir, "file.csv"), ["date", "user"])]
    files = _sum_parts(parts)

    # email.csv: correos enviados y correos con al menos un destinatario fuera de dtaa.com
    ext_re = r"(?:^|;)[^;@]+@(?!dtaa\.com(?:;|$))[^;]+"
    parts = []
    for df in _stream(os.path.join(raw_dir, "email.csv"), ["date", "user", "to", "cc", "bcc"]):
        rcpt = df["to"].fillna("") + ";" + df["cc"].fillna("") + ";" + df["bcc"].fillna("")
        rcpt = rcpt.str.replace(r";+", ";", regex=True).str.strip(";")
        df["emails_sent"] = 1
        df["external_emails"] = rcpt.str.contains(ext_re, regex=True).astype(int)
        parts.append(df.groupby(["user", "day"])[["emails_sent", "external_emails"]].sum().reset_index())
    email = _sum_parts(parts)

    # http.csv (14,5 GB): solo fecha y usuario
    parts = [df.groupby(["user", "day"]).size().rename("http_requests").reset_index()
             for df in _stream(os.path.join(raw_dir, "http.csv"), ["date", "user"])]
    http = _sum_parts(parts)

    daily = pd.concat([logon, unique_pcs, device, files, email, http], axis=1).fillna(0)
    for name, t in [("logon", logon), ("device", device), ("file", files), ("email", email), ("http", http)]:
        log[f"filas_usuario_dia_{name}"] = int(len(t))
    log["eventos_por_fuente"] = {k.replace(".csv", ""): int(v) for k, v in FILAS.items()}
    log["eventos_total"] = int(sum(FILAS.values()))
    return daily, last_active, log


def users_table(raw_dir: str, last_active: pd.Series) -> pd.DataFrame:
    files = sorted(glob.glob(os.path.join(raw_dir, "LDAP", "*.csv")))
    ld = pd.concat([pd.read_csv(f).assign(month=os.path.basename(f)[:-4]) for f in files])
    first = ld.sort_values("month").drop_duplicates("user_id", keep="first")
    last_month = ld.groupby("user_id")["month"].max()
    u = first[["user_id", "role", "functional_unit", "department", "team", "supervisor"]].rename(
        columns={"user_id": "user"})
    u["peer_group"] = u["functional_unit"].astype(str) + " / " + u["department"].astype(str)
    # 14 cuentas sin departamento en LDAP (vicepresidentes y asistentes): forman su propio grupo.
    u.loc[u["department"].isna(), "peer_group"] = "Sin departamento (directivos y asistentes)"
    u["ldap_last_month"] = u["user"].map(last_month)
    u["last_active"] = u["user"].map(last_active)
    return u.reset_index(drop=True)


def labels(answers_dir: str, dataset: str, grid: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Answer key a nivel usuario-día.

    Cada línea del archivo de detalle es un evento malicioso (tipo, id, fecha, usuario, pc, ...).
    Se etiqueta el usuario-día del USUARIO DEL EVENTO: en el escenario 3 el correo masivo sale
    desde la cuenta del supervisor, y ese usuario-día también es actividad maliciosa.
    """
    ins = pd.read_csv(os.path.join(answers_dir, "insiders.csv"))
    ins = ins[ins["dataset"].astype(str) == dataset]
    rows, inc = [], []
    for _, r in ins.iterrows():
        path = glob.glob(os.path.join(answers_dir, "**", r["details"]), recursive=True)[0]
        ev = []
        with open(path, errors="ignore") as fh:
            for line in fh:
                f = line.rstrip("\n").split(",")
                if len(f) >= 4:
                    ev.append((f[0], pd.to_datetime(f[2], format=DATE_FMT), f[3]))
        ev = pd.DataFrame(ev, columns=["type", "date", "user"])
        ev["day"] = ev["date"].dt.normalize()
        ud = ev.groupby(["user", "day"])["type"].agg(lambda s: ";".join(sorted(set(s)))).reset_index()
        ud["scenario"] = int(r["scenario"])
        ud["incident"] = r["user"]
        rows.append(ud)
        inc.append({"incident": r["user"], "scenario": int(r["scenario"]),
                    "start": pd.to_datetime(r["start"], format=DATE_FMT),
                    "end": pd.to_datetime(r["end"], format=DATE_FMT),
                    "accounts": ";".join(sorted(ev["user"].unique())),
                    "malicious_days": int(ud.shape[0]), "events": int(len(ev)),
                    "event_types": ";".join(sorted(ev["type"].unique()))})
    lab = pd.concat(rows).rename(columns={"type": "event_types"})
    lab = lab.groupby(["user", "day"]).agg(scenario=("scenario", "first"), incident=("incident", "first"),
                                           event_types=("event_types", "first")).reset_index()
    out = grid[["user", "day"]].merge(lab, on=["user", "day"], how="left")
    out["is_malicious"] = out["incident"].notna().astype(int)
    out["scenario"] = out["scenario"].fillna(0).astype(int)
    return out, pd.DataFrame(inc)


def build(cfg: dict) -> dict:
    raw, out = cfg["raw_dir"], cfg["processed_dir"]
    os.makedirs(out, exist_ok=True)
    cal = calendar(os.path.join(raw, "logon.csv"), cfg["start"], cfg["end"], cfg["holiday_ratio"])
    daily, last_active, log = aggregate(raw, cal, cfg["work_start"], cfg["work_end"])
    users = users_table(raw, last_active)

    # Rejilla completa usuario x día: la ausencia de eventos es un CERO, no un dato faltante.
    days = pd.date_range(cfg["start"], cfg["end"], freq="D")
    idx = pd.MultiIndex.from_product([sorted(users["user"]), days], names=["user", "day"])
    grid = daily.reindex(idx, fill_value=0)[cfg["signals"]].astype("float32").reset_index()
    lab, inc = labels(cfg["answers_dir"], cfg["dataset"], grid)

    grid.to_parquet(os.path.join(out, "features.parquet"), index=False)
    users.to_parquet(os.path.join(out, "users.parquet"), index=False)
    cal.to_parquet(os.path.join(out, "calendar.parquet"), index=False)
    lab.to_parquet(os.path.join(out, "labels.parquet"), index=False)
    inc.to_parquet(os.path.join(out, "incidents.parquet"), index=False)

    log.update({
        "usuarios": int(users.shape[0]), "dias": int(len(days)),
        "usuario_dia": int(grid.shape[0]),
        "festivos_detectados": cal.loc[cal["holiday"], "day"].dt.strftime("%Y-%m-%d").tolist(),
        "incidentes": int(inc.shape[0]),
        "incidentes_por_escenario": inc["scenario"].value_counts().sort_index().to_dict(),
        "usuario_dia_maliciosos": int(lab["is_malicious"].sum()),
        "prevalencia": float(lab["is_malicious"].mean()),
        "primer_dia_malicioso": str(lab.loc[lab["is_malicious"] == 1, "day"].min().date()),
        "usuarios_que_salen": int((users["last_active"] < days[-1] - pd.Timedelta(days=7)).sum()),
    })
    with open(os.path.join(out, "ingest_log.json"), "w") as fh:
        json.dump(log, fh, indent=2, default=str, ensure_ascii=False)
    return log
