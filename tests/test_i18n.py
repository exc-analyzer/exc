from exc_analyzer import i18n


def test_turkish_catalog_loads():
    original = i18n.get_active_language()
    try:
        assert i18n.set_language("tr")
        assert "belirteci" in i18n.t("commands.key.description")
    finally:
        i18n.set_language(original)


def test_missing_key_falls_back():
    original = i18n.get_active_language()
    try:
        i18n.set_language("en")
        assert i18n.t("commands.does.not.exist") == "commands.does.not.exist"
    finally:
        i18n.set_language(original)
