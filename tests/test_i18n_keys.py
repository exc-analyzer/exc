from exc_analyzer.i18n import t, set_language
def test_analysis_i18n_keys():
    set_language('en')
    assert t("commands.analysis_output.repo_info") == "Repository Information"
    assert t("commands.analysis_output.labels.name") == "Name"
    assert t("commands.analysis_output.completed") == "Completed."
    set_language('tr')
    try:
        assert t("commands.analysis_output.repo_info") == "Depo Bilgileri"
        assert t("commands.analysis_output.labels.name") == "Ad"
        assert t("commands.analysis_output.completed") == "Tamamlandı."
        assert t("commands.security_score.criteria.license") == "Lisans"
        assert t("commands.scan_secrets.no_commits") == "Commit bulunamadı"
        assert t("commands.content_audit.files.readme") == "README"
        assert t("commands.dork_scan.none_found") == "Sonuç bulunamadı."
        assert t("commands.commit_anomaly.headers.sha") == "SHA"
        assert t("commands.user_anomaly.no_activity") == "Yakın zamanda etkinlik bulunamadı."
        assert t("commands.contrib_impact.formula") == "(Skor = Eklenen satır * 0.7 - Silinen satır * 0.3)"
    finally:
        set_language('en')
def test_fallback_mechanism():
    missing_key = "commands.analysis_output.nonexistent_key"
    assert t(missing_key) == missing_key
