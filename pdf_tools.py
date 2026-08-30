# -*- coding: utf-8 -*-
"""توليد تقارير PDF فاخرة باللغة العربية — تشكيل الحروف، اتجاه RTL، وتنسيق ملكي."""
import io
import os
import re
from datetime import date

try:
    import arabic_reshaper
    from bidi.algorithm import get_display
    _HAS_SHAPER = True
except Exception:
    arabic_reshaper = None
    _HAS_SHAPER = False

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape as _land
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas as _pcanvas
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                TableStyle, KeepTogether)

_FONT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fonts")
_WIN_FONTS = r"C:\Windows\Fonts"

_GOLD = colors.HexColor("#D9A441")
_NAVY = colors.HexColor("#14213D")
_NAVY2 = colors.HexColor("#0B1424")
_TEXT = colors.HexColor("#EAF1FC")
_MUTED = colors.HexColor("#8FA1C3")
_LINE = colors.HexColor("#9A7B2F")
_ZEBRA = colors.HexColor("#13223C")
_GREEN = colors.HexColor("#34D399")
_RED = colors.HexColor("#F87171")
_GOLDSOFT = colors.HexColor("#2B2414")


def _path(font_name, win_alt):
    p = os.path.join(_FONT_DIR, font_name)
    if os.path.exists(p):
        return p
    alt = os.path.join(_WIN_FONTS, win_alt)
    return alt if os.path.exists(alt) else p


_REG = _path("Tajawal-Regular.ttf", "tahoma.ttf")
_MED = _path("Tajawal-Medium.ttf", "tahoma.ttf")
_BLD = _path("Tajawal-Bold.ttf", "tahomabd.ttf")
_XBD = _path("Tajawal-ExtraBold.ttf", "tahomabd.ttf")


def _register():
    done = set(pdfmetrics.getRegisteredFontNames())
    for ttf, name in ((_REG, "Tajawal"), (_MED, "Tajawal-Medium"),
                      (_BLD, "Tajawal-Bold"), (_XBD, "Tajawal-XB")):
        if name not in done and os.path.exists(ttf):
            try:
                pdfmetrics.registerFont(TTFont(name, ttf))
                done.add(name)
            except Exception:
                pass
    try:
        pdfmetrics.registerFontFamily("Tajawal", normal="Tajawal", bold="Tajawal-Bold",
                                      italic="Tajawal", boldItalic="Tajawal-Bold")
    except Exception:
        pass


_register()

_AR_RE = re.compile(r"[\u0600-\u06FF\u0750-\u077F\u08A0-\u08FF\uFB50-\uFDFF]")


def ar(s):
    """تشكيل النص العربي + ترتيب الاتجاه الصحيح (RTL)."""
    if s is None:
        s = ""
    s = str(s)
    if _HAS_SHAPER and _AR_RE.search(s):
        return get_display(arabic_reshaper.reshape(s))
    return s


def fmt_num(v):
    try:
        num = float(v)
        return f"{num:,.2f}"
    except (TypeError, ValueError):
        return "" if v is None else str(v)


_HDR = {"company": "", "title": ""}


def _draw_decor(c, page_total):
    w, h = c._pagesize
    c.saveState()
    c.setStrokeColor(_GOLD)
    c.setLineWidth(1.1)
    c.rect(8 * mm, 8 * mm, w - 16 * mm, h - 16 * mm)
    # شريط علوي كحلي + خط ذهبي
    c.setFillColor(_NAVY)
    c.rect(0, h - 21 * mm, w, 21 * mm, stroke=0, fill=1)
    c.setFillColor(_GOLD)
    c.rect(0, h - 22.2 * mm, w, 1.2 * mm, stroke=0, fill=1)
    c.setFont("Tajawal-XB", 12.5)
    c.setFillColor(_GOLD)
    c.drawRightString(w - 16 * mm, h - 12.5 * mm, ar(_HDR.get("company", "")))
    c.setFillColor(_TEXT)
    c.drawCentredString(w / 2, h - 12.5 * mm, ar(_HDR.get("title", "")))
    c.setFont("Tajawal", 7)
    c.setFillColor(_MUTED)
    c.drawCentredString(w / 2, h - 8.8 * mm, ar(_HDR.get("tag", "نظام محاسبة المقاولات المتكامل — تقرير محاسبي رسمي")))
    # شريط سفلي وفوتر
    c.setFillColor(_GOLD)
    c.rect(0, 14.2 * mm, w, 0.8 * mm, stroke=0, fill=1)
    c.setFillColor(_MUTED)
    c.setFont("Tajawal", 7.5)
    c.drawRightString(w - 16 * mm, 9.6 * mm, ar(f"صفحة {c.getPageNumber()} من {page_total}"))
    c.setFont("Tajawal", 7)
    c.drawLeftString(16 * mm, 9.6 * mm, ar("جميع الحقوق محفوظة © " + _HDR.get("company", "")))
    # زوايا ماسية ذهبية
    c.setFillColor(_GOLD)
    for cx, cy in ((10.5 * mm, 10.5 * mm), (w - 14.5 * mm, 10.5 * mm),
                   (10.5 * mm, h - 14.5 * mm), (w - 14.5 * mm, h - 14.5 * mm)):
        c.saveState()
        c.translate(cx, cy)
        c.rotate(45)
        c.rect(-1.4 * mm, -1.4 * mm, 2.8 * mm, 2.8 * mm, stroke=0, fill=1)
        c.restoreState()
    c.restoreState()


class _NumberedCanvas(_pcanvas.Canvas):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self._saved = []

    def showPage(self):
        self._saved.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        total = len(self._saved)
        for state in self._saved:
            self.__dict__.update(state)
            _draw_decor(self, total)
            super().showPage()
        super().save()


sTitle = ParagraphStyle("t", fontName="Tajawal-XB", fontSize=17, leading=22,
                        alignment=1, textColor=_GOLD, spaceAfter=2)
sSub = ParagraphStyle("s", fontName="Tajawal", fontSize=8.5, leading=12,
                      alignment=1, textColor=_MUTED)
sHead = ParagraphStyle("h", fontName="Tajawal-Bold", fontSize=8.5, leading=11,
                       alignment=1, textColor=_TEXT)
sCell = ParagraphStyle("c", fontName="Tajawal", fontSize=8, leading=10.5,
                       alignment=1, textColor=_TEXT)
sNum = ParagraphStyle("n", parent=sCell, alignment=2, fontName="Tajawal-Medium")
sTotal = ParagraphStyle("tt", parent=sCell, textColor=_GOLD, fontName="Tajawal-Bold")
sLine = ParagraphStyle("ln", parent=sCell, alignment=2, fontName="Tajawal-Bold")
sVac = ParagraphStyle("vc", parent=sCell, textColor=colors.transparent)
sBig = ParagraphStyle("b", fontName="Tajawal-XB", fontSize=15, leading=20,
                      alignment=1, textColor=_GOLD)
sP = ParagraphStyle("p", fontName="Tajawal", fontSize=8.5, leading=12,
                    alignment=0, textColor=_TEXT)


def _cells(row, num_cols, is_head=False, is_total=False):
    out = []
    for i, val in enumerate(row):
        st = sHead if is_head else (sTotal if is_total else (sNum if i in num_cols else sCell))
        out.append(Paragraph(ar(fmt_num(val) if isinstance(val, (int, float)) else val), st))
    return out


def _table(headers, rows, num_cols, totals_row=None, col_ratio=None):
    data = []
    if headers:
        data.append(_cells(headers, num_cols, is_head=True))
    for r in rows:
        data.append(_cells(r, num_cols))
    if totals_row is not None:
        data.append(_cells(totals_row, num_cols, is_total=True))
    if not data:
        data = [[Paragraph(ar("لا توجد بيانات"), sCell)]]
    ncol = max(len(x) for x in data)
    widths = None
    if col_ratio:
        widths = col_ratio
    elif ncol:
        widths = [(doc_w := 180 * mm) / ncol] * ncol
    t = Table(data, colWidths=widths, repeatRows=1 if headers else 0, hAlign="CENTER")
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), _NAVY2 if headers else _GOLDSOFT),
        ("TEXTCOLOR", (0, 0), (-1, 0), _TEXT),
        ("FONTNAME", (0, 0), (-1, 0), "Tajawal-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.35, _LINE),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]
    if headers and len(data) > 1:
        style.append(("ROWBACKGROUNDS", (0, 1), (-1, -2), [colors.transparent, _ZEBRA]))
    if totals_row is not None and headers:
        style += [("BACKGROUND", (0, -1), (-1, -1), _GOLDSOFT),
                  ("LINEABOVE", (0, -1), (-1, -1), 0.8, _GOLD)]
    elif totals_row is not None:
        style += [("BACKGROUND", (0, -1), (-1, -1), _GOLDSOFT)]
    t.setStyle(TableStyle(style))
    return t


def _signature_block():
    labels = ["المحاسب المعتمد", "مراجعة الحسابات", "إدارة الشركة"]
    rows = [[Paragraph(ar("الاسم: ................................"), sP),
             Paragraph(ar("الاسم: ................................"), sP),
             Paragraph(ar("الاسم: ................................"), sP),
             ],
            [Paragraph(ar("التوقيع: ............................"), sP),
             Paragraph(ar("التوقيع: ............................"), sP),
             Paragraph(ar("التوقيع: ............................"), sP),
             ],
            [Paragraph(ar(labels[0]), sSub), Paragraph(ar(labels[1]), sSub),
             Paragraph(ar(labels[2]), sSub)]]
    t = Table(rows, colWidths=[60 * mm] * 3, hAlign="CENTER")
    t.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#3A4A6E")),
        ("BACKGROUND", (0, 2), (-1, 2), _NAVY2),
        ("TEXTCOLOR", (0, 2), (-1, 2), _GOLD),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    return t


def build_pdf_report(title, subtitles=(), headers=(), rows=(), num_cols=(),
                     totals_row=None, signatures=False, landscape=False,
                     company="", show_date=True):
    """يولّد تقرير PDF فخمًا. يُرجع BytesIO جاهزًا للإرسال."""
    _HDR.update(company=company or "شركة المقاولات", title=title or "تقرير")
    page_size = _land(A4) if landscape else A4
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=page_size,
                            topMargin=26 * mm, bottomMargin=19 * mm,
                            leftMargin=15 * mm, rightMargin=15 * mm,
                            title=title or "تقرير", author=company or "نظام محاسبة المقاولات",
                            canvasmaker=_NumberedCanvas)
    story = []
    story.append(Paragraph(ar(title or "تقرير"), sTitle))
    subs = list(subtitles or [])
    if show_date:
        subs.append(f"تاريخ الإصدار: {date.today().isoformat()}")
    for s in subs:
        story.append(Paragraph(ar(s), sSub))
    story.append(Spacer(1, 5 * mm))

    if rows or headers:
        story.append(_table(headers, rows, num_cols, totals_row))
        story.append(Spacer(1, 3 * mm))

    if signatures:
        story.append(KeepTogether([Spacer(1, 6 * mm), _signature_block()]))
    doc.build(story)
    buf.seek(0)
    return buf


# ==================================================================
# فاتورة ضريبية فاخرة
# ==================================================================
def tax_invoice_pdf(company, inv_no, inv_date, client_name, ref, method,
                    items, vat_rate, vat_amount, total_net, total_with_vat,
                    notes=""):
    """فاتورة ضريبية رسمية (البيان/المبلغ + ضريبة القيمة المضافة + توقيعات)."""
    _HDR.update(company=company or "شركة المقاولات", title="فاتورة ضريبية")
    page_size = A4
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=page_size,
                            topMargin=26 * mm, bottomMargin=19 * mm,
                            leftMargin=15 * mm, rightMargin=15 * mm,
                            title="فاتورة ضريبية", author=company,
                            canvasmaker=_NumberedCanvas)
    story = []
    story.append(Paragraph(ar("فاتورة ضريبية"), sBig))
    story.append(Spacer(1, 3 * mm))
    # بيانات الفاتورة والعميل
    meta_rows = [
        [Paragraph(ar("رقم الفاتورة"), sSub), Paragraph(ar(inv_no), sNum),
         Paragraph(ar("التاريخ"), sSub), Paragraph(ar(inv_date), sNum),
         Paragraph(ar("طريقة الدفع"), sSub), Paragraph(ar(method), sNum)],
        [Paragraph(ar("العميل"), sSub), Paragraph(ar(client_name), sNum),
         Paragraph(ar("المرجع"), sSub), Paragraph(ar(ref), sNum), "", ""],
    ]
    mt = Table(meta_rows, colWidths=[20 * mm, 40 * mm, 20 * mm, 38 * mm, 20 * mm, 42 * mm])
    mt.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.35, _LINE),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("BACKGROUND", (0, 0), (0, -1), _NAVY2),
        ("BACKGROUND", (2, 0), (2, -1), _NAVY2),
        ("BACKGROUND", (4, 0), (4, -1), _NAVY2),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(mt)
    story.append(Spacer(1, 4 * mm))

    items_rows = [[ar("البيان"), ar("المبلغ")]] + [[ar(d), d2] for d, d2 in items]
    data = []
    for i, rr in enumerate(items_rows):
        is_head = i == 0
        data.append(_cells(rr, num_cols=(1,), is_head=is_head))
    it = Table(data, colWidths=[130 * mm, 50 * mm], repeatRows=1, hAlign="CENTER")
    it.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), _NAVY2),
        ("GRID", (0, 0), (-1, -1), 0.35, _LINE),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.transparent, _ZEBRA]),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(it)
    story.append(Spacer(1, 3 * mm))

    def _sum_row(label, val, gold=False):
        return [Paragraph(ar(label), sTotal if gold else sCell),
                Paragraph(ar(fmt_num(val)), sTotal if gold else sNum)]
    sums = Table([_sum_row("الإجمالي قبل الضريبة", total_net),
                  _sum_row(f"ضريبة القيمة المضافة ({fmt_num(vat_rate)}%)", vat_amount),
                  _sum_row("الإجمالي المستحق مع الضريبة", total_with_vat, gold=True)],
                 colWidths=[130 * mm, 50 * mm], hAlign="CENTER")
    sums.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.35, _LINE),
        ("BACKGROUND", (0, 2), (-1, 2), _GOLDSOFT),
        ("LINEABOVE", (0, 1), (-1, 1), 0.4, _LINE),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(sums)
    if notes:
        story.append(Spacer(1, 4 * mm))
        story.append(Paragraph(ar("ملاحظات: " + notes), sP))
    story.append(KeepTogether([Spacer(1, 8 * mm), _signature_block()]))
    doc.build(story)
    buf.seek(0)
    return buf


# ==================================================================
# تحويل المبلغ إلى كتابة عربية (تفقيط)
# ==================================================================
_UNITS = ["", "واحد", "اثنان", "ثلاثة", "أربعة", "خمسة", "ستة", "سبعة",
          "ثمانية", "تسعة", "عشرة", "أحد عشر", "اثنا عشر", "ثلاثة عشر",
          "أربعة عشر", "خمسة عشر", "ستة عشر", "سبعة عشر", "ثمانية عشر", "تسعة عشر"]
_TENS = ["", "عشرة", "عشرون", "ثلاثون", "أربعون", "خمسون",
         "ستون", "سبعون", "ثمانون", "تسعون"]
_HUNDREDS = ["", "مائة", "مائتان", "ثلاثمائة", "أربعمائة", "خمسمائة",
             "ستمائة", "سبعمائة", "ثمانمائة", "تسعمائة"]


def _three(n):
    out = []
    h, r = divmod(int(n), 100)
    if h:
        out.append(_HUNDREDS[h])
    if r < 20:
        if r:
            out.append(_UNITS[r])
    else:
        t, o = divmod(r, 10)
        out.append((_UNITS[o] + " و" + _TENS[t]) if o else _TENS[t])
    return " ".join(out)


def _scale_word(count, label):
    if label == "ألف":
        return {1: "ألف", 2: "ألفان"}.get(count, _three(count) + " ألف")
    if label == "مليون":
        return {1: "مليون", 2: "مليونان"}.get(count, _three(count) + " مليون")
    if label == "مليار":
        return {1: "مليار", 2: "ملياران"}.get(count, _three(count) + " مليار")
    return _three(count)


def tafqeet(num, currency="جنيه"):
    """يحوّل المبلغ إلى كتابة عربية مفصّلة (تتضمن الكسور)."""
    try:
        num = float(num)
    except (TypeError, ValueError):
        return ""
    if num == 0:
        return "صفر" + (" " + currency if currency else "")
    neg = "سالب " if num < 0 else ""
    num = abs(num)
    integral = int(num)
    frac = int(round((num - integral) * 100))
    if frac == 100:
        integral += 1
        frac = 0
    if not integral:
        words = _three(frac) + " من مائة"
    else:
        n = integral
        parts = []
        for val, label in ((10 ** 9, "مليار"), (10 ** 6, "مليون"), (10 ** 3, "ألف")):
            if n >= val:
                parts.append((n // val, label))
                n %= val
        if n:
            parts.append((n, ""))
        words = " و".join(_scale_word(c, l) for c, l in parts)
        if frac:
            words += " و" + _three(frac) + " من مائة"
    if currency:
        words += " " + currency
        if frac:
            words += " فقط لا غير."
        else:
            words += " فقط لا غير."
    return (neg + words).strip()


# ==================================================================
# سند قبض / سند صرف فاخر
# ==================================================================
def voucher_pdf(kind, vno, vdate, party_label, party, item_label, item,
                amount, method, reference, notes="", currency="جنيه"):
    """ينشئ سند قبض (من عميل) أو سند صرف (لمورد/باطن/رواتب) بتوقيعات.
    kind: 'قبض' أو 'صرف'."""
    kind = "قبض" if kind == "قبض" else "صرف"
    company = _HDR.get("company", "شركة المقاولات")
    _HDR.update(company=company, title=f"سند {kind}", tag="نظام محاسبة المقاولات المتكامل — مستند مالي رسمي")
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                            topMargin=30 * mm, bottomMargin=24 * mm,
                            leftMargin=18 * mm, rightMargin=18 * mm,
                            title=f"سند {kind}", author=company,
                            canvasmaker=_NumberedCanvas)
    story = []
    story.append(Paragraph(ar(f"سند {kind}"), sBig))
    story.append(Spacer(1, 2 * mm))
    story.append(Paragraph(ar(f"رقم السند: {vno}"), sSub))
    story.append(Spacer(1, 4 * mm))

    meta = [
        [Paragraph(ar("بيان المستند"), sSub), Paragraph(ar(item_label), sLine),
         Paragraph(ar("التاريخ"), sSub), Paragraph(ar(vdate), sNum)],
        [Paragraph(ar(party_label), sSub), Paragraph(ar(party), sLine),
         Paragraph(ar("طريقة الدفع"), sSub), Paragraph(ar(method), sNum)],
    ]
    mt = Table(meta, colWidths=[30 * mm, 80 * mm, 25 * mm, 45 * mm])
    mt.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.35, _LINE),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("BACKGROUND", (0, 0), (0, -1), _NAVY2),
        ("BACKGROUND", (2, 0), (2, -1), _NAVY2),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(mt)
    story.append(Spacer(1, 5 * mm))

    # خانة المبلغ الأرقام + الكلمات
    amt_rows = [
        [Paragraph(ar("المبلغ"), sHead), Paragraph(ar(fmt_num(amount)), sBig)],
        [Paragraph(ar(f"المبلغ كتابةً ({currency})"), sHead),
         Paragraph(ar(tafqeet(amount, currency)), sLine)],
        [Paragraph(ar("المرجع"), sHead), Paragraph(ar(reference or "-"), sCell)],
    ]
    at = Table(amt_rows, colWidths=[45 * mm, 135 * mm])
    at.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.35, _LINE),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("BACKGROUND", (0, 0), (0, 0), _GOLDSOFT),
        ("TEXTCOLOR", (1, 0), (1, 0), _GOLD),
        ("BACKGROUND", (0, 1), (-1, 1), _NAVY2),
        ("TEXTCOLOR", (0, 1), (-1, 1), _TEXT),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    story.append(at)
    if notes:
        story.append(Spacer(1, 4 * mm))
        story.append(Paragraph(ar("ملاحظات: " + notes), sP))

    story.append(Spacer(1, 4 * mm))
    ok_row = [[Paragraph(ar("استلمت المبلغ أعلاه"), sP),
               Paragraph(ar("أمين الصندوق"), sP),
               Paragraph(ar("إدارة الشركة"), sP)]]
    if kind == "صرف":
        ok_row = [[Paragraph(ar("المستلم"), sP),
                   Paragraph(ar("أمين الصندوق"), sP),
                   Paragraph(ar("إدارة الشركة"), sP)]]
    ot = Table(ok_row, colWidths=[60 * mm] * 3, hAlign="CENTER")
    ot.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#3A4A6E")),
        ("BACKGROUND", (0, 0), (-1, 0), _NAVY2),
        ("TEXTCOLOR", (0, 0), (-1, 0), _GOLD),
        ("TOPPADDING", (0, 0), (-1, -1), 16),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
    ]))
    story.append(KeepTogether([ot, Spacer(1, 4 * mm), _signature_block()]))
    doc.build(story)
    buf.seek(0)
    return buf