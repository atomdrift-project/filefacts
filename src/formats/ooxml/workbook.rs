//! SpreadsheetML workbook facts: the sheet table and defined names of
//! `xl/workbook.xml` (the keys a BIFF `.xls` already gets from its
//! `BOUNDSHEET` and `NAME` records), and the Excel 4.0 (XLM) macro calls in
//! `xl/macrosheets/*.xml`.

use serde_json::Value as JsonValue;

use crate::metric;
use crate::output::{Metrics, Values};
use crate::value_key;

/// Sheets and names kept per workbook, like the BIFF reader's caps.
const MAX_SHEETS: usize = 1024;
const MAX_NAMES: usize = 1024;

/// The workbook part's sheet table and defined names.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Workbook {
    /// Sheet name and `state` (`visible`, `hidden`, `veryHidden`).
    pub(super) sheets: Vec<(String, String)>,
    pub(super) names: Vec<String>,
}

/// Read `xl/workbook.xml`'s `<sheet>` and `<definedName>` elements.
pub(super) fn parse(doc: &roxmltree::Document<'_>) -> Workbook {
    let mut book = Workbook::default();
    for node in doc.descendants().filter(roxmltree::Node::is_element) {
        match node.tag_name().name() {
            "sheet" if book.sheets.len() < MAX_SHEETS => book.sheets.push((
                node.attribute("name").unwrap_or_default().to_string(),
                node.attribute("state").unwrap_or("visible").to_string(),
            )),
            "definedName" if book.names.len() < MAX_NAMES => {
                if let Some(name) = node.attribute("name") {
                    book.names.push(name.to_string());
                }
            }
            _ => {}
        }
    }
    book
}

/// Emit the sheet and name facts, pushing `veryhidden_sheets` onto
/// `features` when a sheet is very hidden.
pub(super) fn emit(
    book: Workbook,
    values: &mut Values,
    metrics: &mut Metrics,
    features: &mut Vec<&'static str>,
) {
    if !book.sheets.is_empty() {
        let hidden = book.sheets.iter().filter(|(_, s)| s != "visible").count();
        // A very hidden sheet cannot be unhidden from Excel's own UI, only
        // from VBA: the classic place to keep XLM macros out of sight.
        let very_hidden = book
            .sheets
            .iter()
            .filter(|(_, s)| s == "veryHidden")
            .count();
        metrics.insert(metric!("office.sheet_count"), book.sheets.len() as f64);
        if hidden > 0 {
            metrics.insert(metric!("office.hidden_sheet_count"), hidden as f64);
        }
        if very_hidden > 0 {
            features.push("veryhidden_sheets");
            metrics.insert(
                metric!("office.xlm.very_hidden_sheet_count"),
                very_hidden as f64,
            );
        }
        values.insert_key(
            value_key!("office.sheet_names"),
            JsonValue::Array(
                book.sheets
                    .into_iter()
                    .filter(|(name, _)| !name.is_empty())
                    .map(|(name, _)| JsonValue::String(name))
                    .collect(),
            ),
        );
    }
    if !book.names.is_empty() {
        metrics.insert(metric!("office.name_count"), book.names.len() as f64);
        values.insert_key(
            value_key!("office.names"),
            JsonValue::Array(book.names.into_iter().map(JsonValue::String).collect()),
        );
    }
}

/// Whether `name` is an Excel 4.0 macro sheet part.
pub(super) fn is_macrosheet(name: &str) -> bool {
    crate::formats::common::starts_with_ci(name, "xl/macrosheets/")
}

/// XLM calls counted over every macro sheet's formulas: the building blocks
/// of a macro that decodes (`CHAR`), fingerprints its host (`GET.CELL`,
/// `DAY(NOW())`), writes formulas at run time (`FORMULA.FILL`) and calls on
/// (`RUN`).
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct XlmCalls {
    pub(super) char: usize,
    pub(super) day_now: usize,
    pub(super) formula_fill: usize,
    pub(super) get_cell: usize,
    pub(super) run: usize,
}

impl XlmCalls {
    /// Count the calls in one macro sheet part's text.
    pub(super) fn add(&mut self, text: &str) {
        self.char += text.matches("CHAR(").count();
        self.day_now += text.matches("DAY(NOW())").count();
        self.formula_fill += text.matches("FORMULA.FILL").count();
        self.get_cell += text.matches("GET.CELL(").count();
        self.run += text.matches("RUN(").count();
    }

    pub(super) fn emit(&self, metrics: &mut Metrics) {
        for (key, count) in [
            (metric!("office.xlm.char_count"), self.char),
            (metric!("office.xlm.day_now_count"), self.day_now),
            (metric!("office.xlm.formula_fill_count"), self.formula_fill),
            (metric!("office.xlm.get_cell_count"), self.get_cell),
            (metric!("office.xlm.run_count"), self.run),
        ] {
            if count > 0 {
                metrics.insert(key, count as f64);
            }
        }
    }
}

/// Whether a relationship target reaches another host: a network URL, a UNC
/// or authority-relative path, or a `file://` URL naming a host. A local
/// `file:` path and a relative part name are not remote.
pub(super) fn is_remote_target(target: &str) -> bool {
    let t = target.trim();
    let lower = t.to_ascii_lowercase();
    if [
        "http://",
        "https://",
        "ftp://",
        "ftps://",
        "smb://",
        "webdav://",
    ]
    .iter()
    .any(|scheme| lower.starts_with(scheme))
    {
        return true;
    }
    if lower.starts_with("file:") {
        let Some(rest) = lower.strip_prefix("file://") else {
            return false;
        };
        let host = rest.split(['/', '\\']).next().unwrap_or_default();
        let is_drive = host.len() == 2 && host.ends_with(':');
        return !host.is_empty() && host != "localhost" && !is_drive;
    }
    t.starts_with("\\\\") || t.starts_with("//")
}

#[cfg(test)]
mod tests;
