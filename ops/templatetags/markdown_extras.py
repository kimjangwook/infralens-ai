from __future__ import annotations

import bleach
import markdown as markdown_lib
from django import template
from django.utils.safestring import mark_safe

register = template.Library()

ALLOWED_TAGS = set(bleach.sanitizer.ALLOWED_TAGS).union(
    {
        "p",
        "pre",
        "code",
        "h1",
        "h2",
        "h3",
        "h4",
        "hr",
        "br",
        "table",
        "thead",
        "tbody",
        "tr",
        "th",
        "td",
        "blockquote",
    }
)

ALLOWED_ATTRIBUTES = {
    **bleach.sanitizer.ALLOWED_ATTRIBUTES,
    "a": ["href", "title", "rel", "target"],
    "code": ["class"],
}


@register.filter(name="markdown")
def render_markdown(value: str) -> str:
    html = markdown_lib.markdown(
        value or "",
        extensions=["fenced_code", "tables", "sane_lists"],
        output_format="html5",
    )
    cleaned = bleach.clean(
        html,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        protocols=["http", "https", "mailto"],
        strip=True,
    )
    return mark_safe(cleaned)
