"""Regression tests for the static UI assets (v2.1.1 bug class).

The v2.1.0 dashboard shipped with an empty finding-card overlay that
covered the whole page: component display rules (.card-overlay,
.panel) override the UA stylesheet's [hidden] rule, so elements
carrying the hidden attribute rendered anyway. The guard rule
[hidden]{display:none !important} in style.css is what prevents every
future occurrence; these tests pin it and sweep for display rules on
elements that start hidden.
"""
import re
import sys
import unittest
from pathlib import Path

UI = Path(__file__).resolve().parents[1] / 'skills' / 'agents-doctor' / 'scripts' / 'ui' / 'static'


class HiddenGuardTest(unittest.TestCase):
    def test_guard_rule_present(self):
        css = (UI / 'style.css').read_text(encoding='utf-8')
        self.assertRegex(
            css, r'\[hidden\]\s*\{\s*display\s*:\s*none\s*!important',
            'the [hidden]{display:none !important} guard rule must stay '
            'at the top of style.css — it is the v2.1.1 fix')

    def test_guard_before_any_component_rule(self):
        css = (UI / 'style.css').read_text(encoding='utf-8')
        guard = css.find('[hidden]')
        first_rule = re.search(r'\.[\w-]+\s*\{', css)
        self.assertIsNotNone(first_rule)
        self.assertLess(guard, first_rule.start(),
                        'the guard must come first so authors see it')


class HiddenElementsTest(unittest.TestCase):
    """Every element that starts hidden in HTML must have no static
    display rule that would defeat the attribute (belt and braces:
    the !important guard already wins, but a component that both
    starts hidden and sets display is a latent surprise)."""

    def test_hidden_marked_elements_have_no_static_display(self):
        html = (UI / 'index.html').read_text(encoding='utf-8')
        css = (UI / 'style.css').read_text(encoding='utf-8')
        hidden_ids = re.findall(r'id="([\w-]+)"[^>]*\bhidden\b', html)
        self.assertTrue(hidden_ids, 'expected elements to start hidden')
        offenders = []
        for el_id in hidden_ids:
            # a rule like `#id { ... display: X ... }` (not inside a
            # [hidden] selector) would fight the hidden attribute
            for m in re.finditer(r'(#%s)\s*\{([^}]*)\}' % el_id, css):
                body = m.group(2)
                if 'display' in body and '[hidden]' not in m.group(0):
                    offenders.append((el_id, body.strip()[:60]))
        self.assertEqual(offenders, [],
                         'elements that start hidden must not set '
                         'display outside the [hidden] guard: %r' % offenders)




class FaviconTest(unittest.TestCase):
    def test_index_references_favicon(self):
        html = (UI / 'index.html').read_text(encoding='utf-8')
        self.assertIn('rel="icon"', html)
        self.assertIn('/static/favicon.png', html)

    def test_favicon_assets_exist_and_small(self):
        fav = UI / 'favicon.png'
        apple = UI / 'apple-touch-icon.png'
        self.assertTrue(fav.is_file())
        self.assertTrue(apple.is_file())
        # favicons travel inside the plugin zip: keep them light
        self.assertLess(fav.stat().st_size, 64 * 1024)
        self.assertLess(apple.stat().st_size, 96 * 1024)


class BundledFontTest(unittest.TestCase):
    """The web font ships inside the plugin zip, with its license."""

    def test_font_file_present_and_plausible(self):
        font = UI / 'fonts' / 'InterVariable.woff2'
        self.assertTrue(font.is_file())
        blob = font.read_bytes()
        self.assertGreaterEqual(len(blob), 100 * 1024)
        self.assertLessEqual(len(blob), 512 * 1024)
        # WOFF2 signature: a truncated download or an HTML error page
        # in place of the font fails here
        self.assertEqual(blob[:4], b'wOF2')

    def test_license_beside_the_font(self):
        path = UI / 'fonts' / 'LICENSE-Inter.txt'
        self.assertTrue(path.is_file())
        text = path.read_text(encoding='utf-8')
        self.assertIn('SIL OPEN FONT LICENSE', text)


class OfflineAssetsTest(unittest.TestCase):
    """The explorer loads nothing from the network: every resource the
    page and the stylesheet point at is served by the local server."""

    def test_index_references_only_local_resources(self):
        html = (UI / 'index.html').read_text(encoding='utf-8')
        refs = re.findall(r'\b(?:src|href)="([^"]*)"', html)
        self.assertTrue(refs, 'expected resource references')
        for ref in refs:
            self.assertNotIn('http://', ref)
            self.assertNotIn('https://', ref)
            # protocol-relative: //host/path takes the page's scheme
            self.assertFalse(ref.startswith('//'), ref)

    def test_stylesheet_loads_nothing_remote(self):
        css = (UI / 'style.css').read_text(encoding='utf-8')
        # comments are prose and may well mention @import
        body = re.sub(r'/\*.*?\*/', '', css, flags=re.S)
        self.assertNotIn('@import', body)
        urls = re.findall(r'url\(\s*(?:"([^"]*)"|\'([^\']*)\'|([^)"\']*))'
                          r'\s*\)', body, re.I)
        self.assertTrue(urls, 'expected at least the font face')
        for quoted, single, bare in urls:
            target = quoted or single or bare
            # a data URI is inline: the http in its SVG namespace is a
            # name, nothing is fetched
            self.assertNotRegex(target, r'^(?:https?:)?//', target)


class IconConventionTest(unittest.TestCase):
    """Icons are inline SVG in one stroke; a tab keeps its text label,
    so the accessible name of the tab is the label alone."""

    TAB_NAMES = ['Overview', 'Tree', 'TreeMap', 'Instructions',
                 'Findings', 'Simulate', 'Compare', 'History']

    def test_every_tab_has_an_icon_and_a_text_label(self):
        html = (UI / 'index.html').read_text(encoding='utf-8')
        tabs = re.findall(r'<button\b[^>]*\bclass="tab"[^>]*>(.*?)</button>',
                          html, re.S)
        self.assertEqual(len(tabs), len(self.TAB_NAMES))
        labels = []
        for body in tabs:
            self.assertRegex(body, r'<svg\b[^>]*\bclass="icon"')
            label = re.search(r'<span class="tab-label">([^<]*)</span>',
                              body)
            self.assertIsNotNone(label)
            labels.append(label.group(1).strip())
        self.assertEqual(labels, self.TAB_NAMES)

    def test_every_icon_follows_the_convention(self):
        html = (UI / 'index.html').read_text(encoding='utf-8')
        icons = [tag for tag in re.findall(r'<svg\b[^>]*>', html)
                 if re.search(r'\bclass="icon"', tag)]
        self.assertTrue(icons, 'expected inline icons')
        for tag in icons:
            self.assertRegex(tag, r'\bviewBox="0 0 16 16"', tag)
            self.assertRegex(tag, r'\baria-hidden="true"', tag)


if __name__ == '__main__':
    unittest.main()
