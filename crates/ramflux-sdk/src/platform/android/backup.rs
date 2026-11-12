// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Backup exclusion the host application must declare, and a checker for what it declared.
//!
//! Three things keep account state out of a backup or a device transfer, and all three are
//! required: the files live under the no-backup directory (see `storage`), the manifest sets
//! `android:allowBackup="false"`, and the manifest points at rules that exclude every domain
//! for both cloud backup and device-to-device transfer. On Android 12 and later
//! `allowBackup="false"` alone does not stop a device-to-device transfer on every device.
//! The checker reads the application's real manifest and rule files in a build or
//! instrumentation test, so the rule is tested against what ships, not against a comment.

/// Every backup domain Android defines for include and exclude rules.
pub const BACKUP_DOMAINS: [&str; 9] = [
    "root",
    "file",
    "database",
    "sharedpref",
    "external",
    "device_root",
    "device_file",
    "device_database",
    "device_sharedpref",
];

/// `res/xml/ramflux_data_extraction_rules.xml`, referenced by
/// `android:dataExtractionRules` (Android 12, API 31 and later).
pub const DATA_EXTRACTION_RULES_XML: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<data-extraction-rules>
    <cloud-backup>
        <exclude domain="root" path="."/>
        <exclude domain="file" path="."/>
        <exclude domain="database" path="."/>
        <exclude domain="sharedpref" path="."/>
        <exclude domain="external" path="."/>
        <exclude domain="device_root" path="."/>
        <exclude domain="device_file" path="."/>
        <exclude domain="device_database" path="."/>
        <exclude domain="device_sharedpref" path="."/>
    </cloud-backup>
    <device-transfer>
        <exclude domain="root" path="."/>
        <exclude domain="file" path="."/>
        <exclude domain="database" path="."/>
        <exclude domain="sharedpref" path="."/>
        <exclude domain="external" path="."/>
        <exclude domain="device_root" path="."/>
        <exclude domain="device_file" path="."/>
        <exclude domain="device_database" path="."/>
        <exclude domain="device_sharedpref" path="."/>
    </device-transfer>
</data-extraction-rules>
"#;

/// `res/xml/ramflux_full_backup_content.xml`, referenced by `android:fullBackupContent`
/// (Android 11, API 30 and earlier).
pub const FULL_BACKUP_CONTENT_XML: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<full-backup-content>
    <exclude domain="root" path="."/>
    <exclude domain="file" path="."/>
    <exclude domain="database" path="."/>
    <exclude domain="sharedpref" path="."/>
    <exclude domain="external" path="."/>
    <exclude domain="device_root" path="."/>
    <exclude domain="device_file" path="."/>
    <exclude domain="device_database" path="."/>
    <exclude domain="device_sharedpref" path="."/>
</full-backup-content>
"#;

/// What is wrong with the host application's backup declaration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackupRuleDefect {
    /// The manifest does not set `android:allowBackup="false"`.
    AllowBackupNotFalse,
    /// The manifest has no `android:dataExtractionRules` attribute.
    DataExtractionRulesMissing,
    /// The manifest has no `android:fullBackupContent` attribute.
    FullBackupContentMissing,
    /// A rule file contains an `<include>` element.
    IncludesContent,
    /// A section is missing, or does not exclude every domain.
    DomainNotExcluded,
}

fn section<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    let open = xml.find(&format!("<{name}"))?;
    let body = &xml[open..];
    let close = body.find(&format!("</{name}>"))?;
    Some(&body[..close])
}

fn excludes_every_domain(section: &str) -> Result<(), BackupRuleDefect> {
    if section.contains("<include") {
        return Err(BackupRuleDefect::IncludesContent);
    }
    let compact: String = section.chars().filter(|character| !character.is_whitespace()).collect();
    for domain in BACKUP_DOMAINS {
        let whole = format!("<excludedomain=\"{domain}\"path=\".\"/>");
        if !compact.contains(&whole) {
            return Err(BackupRuleDefect::DomainNotExcluded);
        }
    }
    Ok(())
}

/// Check a `data-extraction-rules` file: both `cloud-backup` and `device-transfer` exist and
/// each excludes every domain. A missing section would leave that mode fully enabled.
///
/// # Errors
/// The first defect found.
pub fn check_data_extraction_rules(xml: &str) -> Result<(), BackupRuleDefect> {
    for name in ["cloud-backup", "device-transfer"] {
        excludes_every_domain(section(xml, name).ok_or(BackupRuleDefect::DomainNotExcluded)?)?;
    }
    // A cross-platform transfer section may only repeat the exclusion.
    if let Some(cross_platform) = section(xml, "cross-platform-transfer") {
        excludes_every_domain(cross_platform)?;
    }
    Ok(())
}

/// Check a `full-backup-content` file for Android 11 and earlier.
///
/// # Errors
/// The first defect found.
pub fn check_full_backup_content(xml: &str) -> Result<(), BackupRuleDefect> {
    excludes_every_domain(
        section(xml, "full-backup-content").ok_or(BackupRuleDefect::DomainNotExcluded)?,
    )
}

/// Check the `<application>` element of a merged `AndroidManifest.xml`.
///
/// # Errors
/// The first defect found.
pub fn check_manifest(manifest_xml: &str) -> Result<(), BackupRuleDefect> {
    let compact: String =
        manifest_xml.chars().filter(|character| !character.is_whitespace()).collect();
    if !compact.contains("android:allowBackup=\"false\"") {
        return Err(BackupRuleDefect::AllowBackupNotFalse);
    }
    if !compact.contains("android:dataExtractionRules=\"@xml/") {
        return Err(BackupRuleDefect::DataExtractionRulesMissing);
    }
    if !compact.contains("android:fullBackupContent=\"@xml/") {
        return Err(BackupRuleDefect::FullBackupContentMissing);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MANIFEST: &str = r#"<manifest xmlns:android="http://schemas.android.com/apk/res/android">
        <application
            android:allowBackup="false"
            android:dataExtractionRules="@xml/ramflux_data_extraction_rules"
            android:fullBackupContent="@xml/ramflux_full_backup_content" />
    </manifest>"#;

    #[test]
    fn shipped_rules_exclude_every_domain_for_cloud_and_device_transfer() {
        assert_eq!(check_data_extraction_rules(DATA_EXTRACTION_RULES_XML), Ok(()));
        assert_eq!(check_full_backup_content(FULL_BACKUP_CONTENT_XML), Ok(()));
        assert_eq!(check_manifest(MANIFEST), Ok(()));
    }

    #[test]
    fn missing_device_transfer_section_is_a_defect() {
        let cut = DATA_EXTRACTION_RULES_XML.find("<device-transfer>").unwrap_or(0);
        let cloud_only = format!("{}</data-extraction-rules>", &DATA_EXTRACTION_RULES_XML[..cut]);
        assert_eq!(
            check_data_extraction_rules(&cloud_only),
            Err(BackupRuleDefect::DomainNotExcluded)
        );
    }

    #[test]
    fn one_missing_domain_or_one_include_is_a_defect() {
        for domain in BACKUP_DOMAINS {
            let line = format!("        <exclude domain=\"{domain}\" path=\".\"/>\n");
            let without = FULL_BACKUP_CONTENT_XML.replace(&line, "");
            assert_eq!(
                check_full_backup_content(&without),
                Err(BackupRuleDefect::DomainNotExcluded),
                "{domain}"
            );
        }
        let included = DATA_EXTRACTION_RULES_XML.replacen(
            "<cloud-backup>",
            "<cloud-backup><include domain=\"file\" path=\".\"/>",
            1,
        );
        assert_eq!(check_data_extraction_rules(&included), Err(BackupRuleDefect::IncludesContent));
    }

    #[test]
    fn manifest_defects_are_named() {
        let allowed =
            MANIFEST.replace("android:allowBackup=\"false\"", "android:allowBackup=\"true\"");
        assert_eq!(check_manifest(&allowed), Err(BackupRuleDefect::AllowBackupNotFalse));
        let no_rules = MANIFEST
            .replace("android:dataExtractionRules=\"@xml/ramflux_data_extraction_rules\"", "");
        assert_eq!(check_manifest(&no_rules), Err(BackupRuleDefect::DataExtractionRulesMissing));
        let no_legacy =
            MANIFEST.replace("android:fullBackupContent=\"@xml/ramflux_full_backup_content\"", "");
        assert_eq!(check_manifest(&no_legacy), Err(BackupRuleDefect::FullBackupContentMissing));
    }
}
