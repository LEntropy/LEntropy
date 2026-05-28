"""NAC PPT 생성 스크립트"""
from pptx import Presentation
from pptx.util import Inches, Pt, Emu
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN
from pptx.util import Inches, Pt
import copy

# ── 색상 팔레트 ────────────────────────────────────────────────────────────────
C_DARK    = RGBColor(0x1A, 0x1A, 0x2E)   # 딥 네이비 (배경)
C_ACCENT  = RGBColor(0x16, 0x21, 0x3E)   # 미드 네이비
C_BLUE    = RGBColor(0x0F, 0x3D, 0x91)   # 강조 블루
C_CYAN    = RGBColor(0x00, 0xB4, 0xD8)   # 밝은 시안
C_GREEN   = RGBColor(0x00, 0xC8, 0x9A)   # 에메랄드 그린
C_WHITE   = RGBColor(0xFF, 0xFF, 0xFF)
C_LGRAY   = RGBColor(0xCC, 0xCC, 0xCC)
C_YELLOW  = RGBColor(0xFF, 0xD6, 0x00)
C_RED     = RGBColor(0xFF, 0x4D, 0x6D)
C_ORANGE  = RGBColor(0xFF, 0x8C, 0x42)

W = Inches(13.33)   # 와이드 16:9
H = Inches(7.5)

prs = Presentation()
prs.slide_width  = W
prs.slide_height = H

BLANK = prs.slide_layouts[6]   # 완전 빈 레이아웃


# ── 헬퍼 함수 ─────────────────────────────────────────────────────────────────

def add_rect(slide, x, y, w, h, fill=C_DARK, alpha=None):
    shape = slide.shapes.add_shape(
        1,  # MSO_SHAPE_TYPE.RECTANGLE
        Inches(x), Inches(y), Inches(w), Inches(h)
    )
    shape.fill.solid()
    shape.fill.fore_color.rgb = fill
    shape.line.fill.background()
    return shape


def add_text(slide, text, x, y, w, h,
             size=18, bold=False, color=C_WHITE,
             align=PP_ALIGN.LEFT, wrap=True):
    txb = slide.shapes.add_textbox(Inches(x), Inches(y), Inches(w), Inches(h))
    txb.word_wrap = wrap
    tf = txb.text_frame
    tf.word_wrap = wrap
    p = tf.paragraphs[0]
    p.alignment = align
    run = p.add_run()
    run.text = text
    run.font.size = Pt(size)
    run.font.bold = bold
    run.font.color.rgb = color
    return txb


def add_multiline(slide, lines, x, y, w, h, size=16, color=C_WHITE,
                  bold_first=False, line_spacing=None):
    """lines: list of (text, bold, color_override)"""
    txb = slide.shapes.add_textbox(Inches(x), Inches(y), Inches(w), Inches(h))
    txb.word_wrap = True
    tf = txb.text_frame
    tf.word_wrap = True
    first = True
    for item in lines:
        if isinstance(item, str):
            text, b, c = item, (bold_first and first), color
        else:
            text, b, c = item[0], item[1], item[2] if len(item) > 2 else color
        if first:
            p = tf.paragraphs[0]
        else:
            p = tf.add_paragraph()
        p.alignment = PP_ALIGN.LEFT
        run = p.add_run()
        run.text = text
        run.font.size = Pt(size)
        run.font.bold = b
        run.font.color.rgb = c
        if line_spacing:
            p.line_spacing = Pt(line_spacing)
        first = False
    return txb


def bg(slide, color=C_DARK):
    add_rect(slide, 0, 0, 13.33, 7.5, fill=color)


def accent_bar(slide, y=1.1, h=0.06, color=C_CYAN):
    add_rect(slide, 0.5, y, 12.33, h, fill=color)


def slide_header(slide, title, subtitle=None, tag=None):
    accent_bar(slide, y=0.55)
    add_text(slide, title, 0.5, 0.65, 11, 0.7,
             size=32, bold=True, color=C_WHITE)
    if subtitle:
        add_text(slide, subtitle, 0.5, 1.25, 11, 0.4,
                 size=16, color=C_CYAN)
    if tag:
        add_text(slide, tag, 11.2, 0.55, 1.8, 0.45,
                 size=13, color=C_LGRAY, align=PP_ALIGN.RIGHT)


def bullet_box(slide, items, x, y, w, h,
               box_color=C_ACCENT, title=None, title_color=C_CYAN):
    add_rect(slide, x, y, w, h, fill=box_color)
    ty = y + 0.12
    if title:
        add_text(slide, title, x + 0.18, ty, w - 0.3, 0.4,
                 size=16, bold=True, color=title_color)
        ty += 0.42
    lines = []
    for item in items:
        if isinstance(item, tuple):
            lines.append(item)
        else:
            lines.append(("  • " + item, False, C_WHITE))
    add_multiline(slide, lines, x + 0.15, ty, w - 0.3,
                  h - (ty - y) - 0.1, size=14, color=C_WHITE)


def note(slide, text):
    slide.notes_slide.notes_text_frame.text = text


# ══════════════════════════════════════════════════════════════════════════════
# SLIDE 1 — 표지
# ══════════════════════════════════════════════════════════════════════════════
sl = prs.slides.add_slide(BLANK)
bg(sl)

# 배경 장식 블록
add_rect(sl, 0, 0, 3.5, 7.5, fill=C_BLUE)
add_rect(sl, 3.5, 0, 0.08, 7.5, fill=C_CYAN)

# 왼쪽 아이콘 느낌 텍스트
add_text(sl, "🔒", 0.5, 1.5, 2.5, 1.5, size=72, align=PP_ALIGN.CENTER)

# 메인 제목
add_text(sl, "NAC", 4.0, 1.2, 9.0, 1.2,
         size=72, bold=True, color=C_CYAN)
add_text(sl, "Network Access Control", 4.0, 2.3, 9.0, 0.55,
         size=24, color=C_LGRAY)

add_rect(sl, 4.0, 2.95, 8.8, 0.06, fill=C_CYAN)

add_text(sl, "NAC 개념 설명 및 활용 방안과 개발 개요", 4.0, 3.1, 9.0, 0.6,
         size=22, bold=True, color=C_WHITE)
add_text(sl, "발표 시간 30분  |  2026", 4.0, 3.75, 9.0, 0.4,
         size=15, color=C_LGRAY)

add_text(sl, "LEntropy NAC Platform v0.1", 4.0, 6.8, 9.0, 0.4,
         size=13, color=C_LGRAY)

note(sl, """[표지 — 약 1분]

안녕하세요. 오늘은 NAC, 즉 네트워크 접근 제어 시스템의 개념과 활용 방안, 그리고 저희가 직접 개발한 LEntropy NAC 플랫폼의 개발 개요를 소개해 드리겠습니다.
발표는 총 30분으로 진행되며, 이론 개념 → 실무 활용 → 개발 구현 순서로 설명드리겠습니다.
궁금하신 점은 발표 후 Q&A 시간에 질문해 주시기 바랍니다.""")

# ══════════════════════════════════════════════════════════════════════════════
# SLIDE 2 — 목차
# ══════════════════════════════════════════════════════════════════════════════
sl = prs.slides.add_slide(BLANK)
bg(sl)
slide_header(sl, "목차", "Table of Contents", "02")

sections = [
    ("1부  개념", "NAC란 무엇인가?\n왜 NAC가 필요한가?", C_BLUE),
    ("2부  원리", "동작 방식\n에이전트리스 vs 에이전트", C_CYAN),
    ("3부  활용", "기업 / 교육 / 의료 환경\n실제 적용 시나리오", C_GREEN),
    ("4부  개발", "아키텍처 & 기술 스택\n컴포넌트 구현 현황", C_ORANGE),
    ("5부  결론", "핵심 가치 요약\n향후 로드맵", C_YELLOW),
]

xs = [0.4, 2.9, 5.4, 7.9, 10.4]
for i, (title, body, color) in enumerate(sections):
    x = xs[i]
    add_rect(sl, x, 1.7, 2.3, 4.5, fill=C_ACCENT)
    add_rect(sl, x, 1.7, 2.3, 0.45, fill=color)
    add_text(sl, title, x + 0.1, 1.72, 2.1, 0.4,
             size=15, bold=True, color=C_DARK)
    add_text(sl, body, x + 0.12, 2.25, 2.1, 3.7,
             size=13, color=C_WHITE)

note(sl, """[목차 — 약 30초]

발표는 크게 5개 파트로 구성됩니다.
1부에서는 NAC의 개념, 2부에서는 기술적 동작 원리, 3부에서는 다양한 산업 환경에서의 활용 방안, 4부에서는 실제 개발 내용, 마지막으로 5부에서 결론 및 향후 계획을 말씀드리겠습니다.""")

# ══════════════════════════════════════════════════════════════════════════════
# SLIDE 3 — NAC란 무엇인가?
# ══════════════════════════════════════════════════════════════════════════════
sl = prs.slides.add_slide(BLANK)
bg(sl)
slide_header(sl, "NAC란 무엇인가?", "Network Access Control 정의", "03")

add_rect(sl, 0.4, 1.7, 12.5, 1.2, fill=C_BLUE)
add_text(sl,
         "\"네트워크에 접속하려는 모든 장치를 식별·인증·검사하여\n정책에 따라 접속을 허용/차단/격리하는 보안 프레임워크\"",
         0.6, 1.78, 12.1, 1.05,
         size=18, bold=True, color=C_WHITE, align=PP_ALIGN.CENTER)

cols = [
    ("🔍 식별 (Identify)", "• 네트워크에 연결된 모든 장치 탐지\n• MAC 주소, IP, OS 정보 수집\n• 에이전트 또는 패킷 분석으로 탐지"),
    ("✅ 인증 (Authenticate)", "• 사용자/장치 신원 확인\n• 802.1x RADIUS 프로토콜\n• LDAP/AD 계정 연동"),
    ("🛡️ 정책 (Policy)", "• 단말 상태에 따른 접근 규칙 적용\n• 컴플라이언스 검사 (암호화, 패치 등)\n• 실시간 정책 변경 반영"),
    ("🚫 제어 (Control)", "• 미인증 장치 자동 차단\n• 격리 네트워크(VLAN) 이동\n• ARP 스푸핑 기반 L2 차단"),
]
for i, (title, body) in enumerate(cols):
    x = 0.4 + i * 3.2
    add_rect(sl, x, 3.1, 3.05, 3.6, fill=C_ACCENT)
    add_text(sl, title, x + 0.12, 3.15, 2.8, 0.5,
             size=15, bold=True, color=C_CYAN)
    add_text(sl, body, x + 0.12, 3.7, 2.8, 2.9,
             size=13, color=C_WHITE)

note(sl, """[NAC 정의 — 약 2분]

NAC는 네트워크 접근 제어(Network Access Control)의 약자입니다.
한 마디로 정의하면, 네트워크에 접속하려는 모든 장치를 식별하고, 인증하고, 검사하여 보안 정책에 따라 접속을 허용하거나 차단하는 보안 시스템입니다.

핵심 기능은 4가지입니다.
첫째, 식별 — 네트워크에 연결된 모든 장치를 자동으로 탐지합니다.
둘째, 인증 — 802.1x 표준이나 LDAP을 통해 사용자와 장치의 신원을 확인합니다.
셋째, 정책 — 단말의 보안 상태에 따라 접근 수준을 다르게 적용합니다.
넷째, 제어 — 정책을 위반한 장치를 실시간으로 차단하거나 격리합니다.""")

# ══════════════════════════════════════════════════════════════════════════════
# SLIDE 4 — 왜 NAC가 필요한가?
# ══════════════════════════════════════════════════════════════════════════════
sl = prs.slides.add_slide(BLANK)
bg(sl)
slide_header(sl, "왜 NAC가 필요한가?", "보안 위협 현황과 네트워크 변화", "04")

threats = [
    "🖥️ BYOD 확산  —  직원 개인 기기(스마트폰, 노트북)의 업무망 접속",
    "🌐 IoT 폭증  —  IP카메라, 프린터, 스마트 센서 등 비관리 장치 급증",
    "🦠 내부 위협  —  악성코드 감염 단말이 내부망을 통해 횡적 이동",
    "🔓 미인증 접속  —  퇴직자 노트북, 외부 방문자 USB 등 비인가 장치",
    "📋 컴플라이언스  —  개인정보보호법·정보보호관리체계(ISMS-P) 요구사항",
]
for i, t in enumerate(threats):
    add_rect(sl, 0.5, 1.65 + i * 0.98, 12.3, 0.82, fill=C_ACCENT)
    add_rect(sl, 0.5, 1.65 + i * 0.98, 0.15, 0.82, fill=C_RED)
    add_text(sl, t, 0.78, 1.68 + i * 0.98, 11.8, 0.75,
             size=16, color=C_WHITE)

add_rect(sl, 0.5, 6.6, 12.3, 0.65, fill=C_BLUE)
add_text(sl, "🎯  NAC 도입 시  →  미인증 장치 접속 차단 + 내부망 침해 범위 최소화 + 규정 준수 자동화",
         0.65, 6.65, 12.0, 0.55, size=15, bold=True, color=C_WHITE)

note(sl, """[왜 NAC가 필요한가 — 약 2분]

현대 기업 네트워크는 과거와 완전히 달라졌습니다.
직원 개인 스마트폰이 회사 Wi-Fi에 연결되고, 공장 바닥에는 수십 개의 IoT 센서가 깔려 있습니다.
이런 환경에서 관리되지 않는 장치 하나가 악성코드에 감염되면, 내부망 전체가 위험에 노출됩니다.

또한 개인정보보호법과 ISMS-P 등 법적 요구사항도 엄격해졌습니다.
네트워크 접근 이력을 기록하고, 비인가 장치 접속을 차단했다는 증거를 제시해야 합니다.
NAC는 이 모든 요구사항을 자동으로 처리해 줍니다.""")

# ══════════════════════════════════════════════════════════════════════════════
# SLIDE 5 — NAC 동작 원리 (전체 흐름)
# ══════════════════════════════════════════════════════════════════════════════
sl = prs.slides.add_slide(BLANK)
bg(sl)
slide_header(sl, "NAC 동작 원리", "단말 접속부터 정책 적용까지", "05")

steps = [
    (C_CYAN,   "①  탐지",     "장치가 네트워크에\n연결됨\nARP/DHCP 감지"),
    (C_BLUE,   "②  식별",     "MAC 주소, OS,\n호스트명 수집\nOS 핑거프린팅"),
    (C_GREEN,  "③  인증",     "802.1x RADIUS\n또는 Captive Portal\n사용자 확인"),
    (C_ORANGE, "④  정책평가", "컴플라이언스 검사\n화이트리스트 확인\n위험도 판정"),
    (C_RED,    "⑤  제어",     "허용 / 차단 / 격리\nARP 스푸핑 실행\n실시간 적용"),
]
for i, (color, title, body) in enumerate(steps):
    x = 0.4 + i * 2.55
    add_rect(sl, x, 1.8, 2.3, 4.5, fill=C_ACCENT)
    add_rect(sl, x, 1.8, 2.3, 0.5, fill=color)
    add_text(sl, title, x + 0.1, 1.83, 2.1, 0.44,
             size=17, bold=True, color=C_DARK)
    add_text(sl, body, x + 0.15, 2.38, 2.0, 3.8,
             size=14, color=C_WHITE)
    if i < 4:
        add_text(sl, "▶", x + 2.3, 3.7, 0.25, 0.4,
                 size=18, bold=True, color=C_CYAN, align=PP_ALIGN.CENTER)

add_rect(sl, 0.4, 6.55, 12.5, 0.65, fill=RGBColor(0x0F, 0x3D, 0x91))
add_text(sl, "모든 단계는 실시간으로 처리되며 감사 로그(Audit Log)에 기록됩니다",
         0.6, 6.6, 12.1, 0.55, size=15, color=C_WHITE, align=PP_ALIGN.CENTER)

note(sl, """[동작 원리 — 약 3분]

NAC의 동작은 5단계로 이루어집니다.

1단계 탐지: 장치가 네트워크에 연결되는 순간, ARP 브로드캐스트나 DHCP 요청을 통해 자동으로 감지됩니다.
2단계 식별: MAC 주소, IP, OS 종류를 수집합니다. 에이전트 없이도 DHCP 옵션 분석으로 Windows인지 Linux인지 구분할 수 있습니다.
3단계 인증: 802.1x 프로토콜로 RADIUS 서버에 인증을 요청하거나, 웹 브라우저를 캡티브 포털로 리다이렉트하여 로그인을 요구합니다.
4단계 정책 평가: 보안 패치 적용 여부, 암호화 설정, 화이트리스트 등록 여부 등을 검사합니다.
5단계 제어: 검사 결과에 따라 허용, 차단, 또는 격리 네트워크로 이동시킵니다.
모든 과정은 감사 로그에 자동 기록됩니다.""")

# ══════════════════════════════════════════════════════════════════════════════
# SLIDE 6 — 에이전트리스 vs 에이전트 방식
# ══════════════════════════════════════════════════════════════════════════════
sl = prs.slides.add_slide(BLANK)
bg(sl)
slide_header(sl, "두 가지 제어 방식", "에이전트리스 vs 에이전트 기반", "06")

# 왼쪽 에이전트리스
add_rect(sl, 0.4, 1.7, 5.9, 5.5, fill=C_ACCENT)
add_rect(sl, 0.4, 1.7, 5.9, 0.55, fill=C_CYAN)
add_text(sl, "에이전트리스 (Agentless)", 0.55, 1.73, 5.6, 0.48,
         size=17, bold=True, color=C_DARK)

lines_l = [
    "동작 방식",
    "  • sensor 서비스가 ARP/DHCP 패킷 수동 감청",
    "  • pnet 라이브러리로 raw socket 캡처",
    "  • DHCP Option 55 분석 → OS 핑거프린팅",
    "",
    "제어 방식",
    "  • enforcement 서비스가 ARP 스푸핑 실행",
    "  • 차단 대상 PC에 위조 ARP 응답 전송",
    "  • 스위치/AP 설정 변경 없이 소프트웨어로 차단",
    "",
    "장점  ✓ 설치 불필요 · 즉시 적용",
    "단점  ✗ 컴플라이언스 정보 부족",
]
ty = 2.35
for line in lines_l:
    bold = line in ("동작 방식", "제어 방식")
    color = C_CYAN if bold else (C_GREEN if "✓" in line else (C_RED if "✗" in line else C_WHITE))
    add_text(sl, line, 0.6, ty, 5.5, 0.28,
             size=13, bold=bold, color=color)
    ty += 0.29

# 가운데 VS
add_text(sl, "VS", 6.4, 3.8, 0.5, 0.5,
         size=24, bold=True, color=C_YELLOW, align=PP_ALIGN.CENTER)

# 오른쪽 에이전트 기반
add_rect(sl, 7.0, 1.7, 5.9, 5.5, fill=C_ACCENT)
add_rect(sl, 7.0, 1.7, 5.9, 0.55, fill=C_GREEN)
add_text(sl, "에이전트 기반 (Agent)", 7.15, 1.73, 5.6, 0.48,
         size=17, bold=True, color=C_DARK)

lines_r = [
    "동작 방식",
    "  • PC에 endpoint-agent 데몬 설치",
    "  • 시스템 정보 수집 (OS, 메모리, 버전)",
    "  • gRPC로 agent-gateway에 주기적 보고",
    "",
    "제어 방식",
    "  • 에이전트는 상태 보고만 담당",
    "  • 실제 차단은 enforcement가 수행",
    "  • 컴플라이언스 위반 시 자동 격리",
    "",
    "장점  ✓ 상세 컴플라이언스 정보 수집",
    "단점  ✗ 각 PC에 설치 필요",
]
ty = 2.35
for line in lines_r:
    bold = line in ("동작 방식", "제어 방식")
    color = C_GREEN if bold else (C_GREEN if "✓" in line else (C_RED if "✗" in line else C_WHITE))
    add_text(sl, line, 7.15, ty, 5.6, 0.28,
             size=13, bold=bold, color=color)
    ty += 0.29

note(sl, """[두 가지 방식 — 약 3분]

NAC는 두 가지 방식으로 동작합니다.

에이전트리스 방식은 PC에 아무것도 설치하지 않습니다.
네트워크 스위치에 흐르는 ARP, DHCP 패킷을 sensor 서비스가 수동으로 감청하여 장치를 탐지합니다.
차단이 필요하면 enforcement 서비스가 ARP 스푸핑을 실행합니다.
ARP 스푸핑이란, PC에게 '게이트웨이의 MAC 주소가 우리 서버입니다'라고 거짓 응답을 보내는 기법입니다.
PC는 이후 인터넷으로 보내는 모든 패킷을 enforcement 서버에 보내게 되고, 서버는 이를 버립니다.

에이전트 기반 방식은 PC에 endpoint-agent 프로그램을 설치합니다.
에이전트는 30~60초마다 자신의 보안 상태를 gRPC로 서버에 보고합니다.
중요한 점은, 에이전트 자체는 네트워크를 끊지 않습니다.
차단 결정은 policy-manager가 하고, 실행은 enforcement가 합니다.

두 방식은 함께 사용할 수 있으며, 에이전트 설치 여부에 따라 얻을 수 있는 정보의 깊이가 달라집니다.""")

# ══════════════════════════════════════════════════════════════════════════════
# SLIDE 7 — 활용 방안 개요
# ══════════════════════════════════════════════════════════════════════════════
sl = prs.slides.add_slide(BLANK)
bg(sl)
slide_header(sl, "NAC 활용 방안", "산업별 적용 시나리오", "07")

add_rect(sl, 0.4, 1.7, 12.5, 0.55, fill=C_BLUE)
add_text(sl, "NAC는 네트워크가 존재하는 모든 환경에 적용 가능합니다",
         0.6, 1.73, 12.1, 0.48,
         size=16, bold=True, color=C_WHITE, align=PP_ALIGN.CENTER)

sectors = [
    ("🏢 기업",        C_BLUE,   "BYOD 정책 집행\n퇴직자 장치 즉시 차단\n부서별 접근 권한 분리\nVPN 연동 보안 강화"),
    ("🎓 교육기관",    C_CYAN,   "학생/교직원 구분 접속\n실습실 PC 자동 등록\n시험 기간 외부 접속 차단\n캠퍼스 Wi-Fi 인증"),
    ("🏥 의료기관",    C_GREEN,  "의료기기 별도 망 격리\nEMR 시스템 접근 제어\n개인정보 유출 방지\nHIPAA 컴플라이언스"),
    ("🏭 제조/공장",   C_ORANGE, "OT/IT 망 분리\nPLC·SCADA 장치 보호\n외주 업체 임시 접속\n산업 제어망 무단 접속 차단"),
    ("🏛️ 공공기관",   C_RED,    "국가보안망 접근 제어\n출입 인증 연동\n보안 등급별 망 분리\n감사 로그 법적 증거 보존"),
]
xs2 = [0.4, 2.85, 5.3, 7.75, 10.2]
for i, (title, color, body) in enumerate(sectors):
    x = xs2[i]
    add_rect(sl, x, 2.38, 2.3, 4.7, fill=C_ACCENT)
    add_rect(sl, x, 2.38, 2.3, 0.7, fill=color)
    add_text(sl, title, x + 0.1, 2.4, 2.1, 0.65,
             size=15, bold=True, color=C_DARK if color != C_BLUE else C_WHITE)
    add_text(sl, body, x + 0.12, 3.15, 2.1, 3.8,
             size=13, color=C_WHITE)

note(sl, """[활용 방안 — 약 2분]

NAC는 특정 산업에 국한되지 않고 네트워크가 있는 모든 환경에 적용됩니다.

기업 환경에서는 직원 개인 기기 접속 정책 집행과 퇴직자 장치의 즉시 차단이 주요 사용 사례입니다.
교육기관은 학생과 교직원의 네트워크 권한을 자동으로 분리합니다.
병원은 의료기기를 별도 망에 격리하여 랜섬웨어 공격으로부터 보호합니다.
제조 공장은 OT 네트워크와 IT 네트워크를 분리하여 산업 제어 시스템을 보호합니다.
공공기관은 법적 감사 요건을 충족하기 위한 접속 이력 보존에 활용합니다.""")

# ══════════════════════════════════════════════════════════════════════════════
# SLIDE 8 — 기업 환경 상세 시나리오
# ══════════════════════════════════════════════════════════════════════════════
sl = prs.slides.add_slide(BLANK)
bg(sl)
slide_header(sl, "활용 시나리오 — 기업 환경", "BYOD & 내부 보안 관리", "08")

scenarios = [
    ("시나리오 1", "C_CYAN",  "BYOD 직원 스마트폰",
     "• Wi-Fi 연결 시 Captive Portal 표시\n• 회사 계정으로 인증 후 업무망 접속 허용\n• 미인증 시 인터넷 전용 Guest VLAN으로 격리"),
    ("시나리오 2", "C_GREEN", "협력업체 방문자 노트북",
     "• MAC 주소 기반 자동 탐지\n• 화이트리스트 미등록 → 즉시 차단\n• 임시 접속권 발급 후 만료 시 자동 해제"),
    ("시나리오 3", "C_ORANGE","퇴직자 장치 접속 시도",
     "• LDAP 계정 비활성화 → RADIUS 거부\n• 이전에 등록된 MAC도 정책으로 차단\n• 보안팀 실시간 알림 발송"),
    ("시나리오 4", "C_RED",   "악성코드 감염 PC",
     "• endpoint-agent가 이상 프로세스 감지\n• policy-manager에 위험 상태 보고\n• 자동 quarantine 격리 + 감사 로그 기록"),
]
color_map = {"C_CYAN": C_CYAN, "C_GREEN": C_GREEN, "C_ORANGE": C_ORANGE, "C_RED": C_RED}

for i, (title, ckey, subtitle, body) in enumerate(scenarios):
    row = i // 2
    col = i % 2
    x = 0.4 + col * 6.45
    y = 1.75 + row * 2.65
    add_rect(sl, x, y, 6.2, 2.45, fill=C_ACCENT)
    add_rect(sl, x, y, 6.2, 0.48, fill=color_map[ckey])
    add_text(sl, f"{title}  {subtitle}", x + 0.15, y + 0.04, 5.9, 0.42,
             size=15, bold=True, color=C_DARK)
    add_text(sl, body, x + 0.15, y + 0.55, 5.9, 1.82,
             size=13, color=C_WHITE)

note(sl, """[기업 환경 시나리오 — 약 3분]

실제 기업 환경에서 발생하는 4가지 대표 시나리오를 설명합니다.

첫 번째, BYOD 직원 스마트폰입니다. 스마트폰이 Wi-Fi에 연결되면 캡티브 포털이 표시됩니다. 회사 계정으로 로그인하면 업무망에 접속되고, 그렇지 않으면 인터넷만 가능한 게스트 영역으로 격리됩니다.

두 번째, 협력업체 방문자입니다. 방문자 노트북이 연결되면 화이트리스트를 확인합니다. 미등록 장치는 즉시 차단되고, 필요한 경우 임시 접속권을 발급할 수 있습니다.

세 번째, 퇴직자 장치 접속입니다. 퇴직자의 AD 계정이 비활성화되면 RADIUS 인증이 거부됩니다. 이전에 등록된 MAC 주소도 정책에 의해 차단됩니다.

네 번째, 악성코드 감염 PC입니다. endpoint-agent가 이상 징후를 감지하여 서버에 보고하면, policy-manager가 해당 장치를 즉시 격리합니다.""")

# ══════════════════════════════════════════════════════════════════════════════
# SLIDE 9 — 개발 아키텍처 개요
# ══════════════════════════════════════════════════════════════════════════════
sl = prs.slides.add_slide(BLANK)
bg(sl)
slide_header(sl, "개발 개요 — 시스템 아키텍처", "LEntropy NAC Platform v0.1", "09")

# 아키텍처 다이어그램을 박스+화살표로 표현
# 상단: 외부 접점
add_rect(sl, 0.4,  1.75, 2.4, 0.7, fill=C_BLUE)
add_text(sl, "🌐 Wi-Fi / 유선\n스위치", 0.45, 1.78, 2.3, 0.65,
         size=12, color=C_WHITE, align=PP_ALIGN.CENTER)

add_rect(sl, 3.2,  1.75, 2.4, 0.7, fill=C_BLUE)
add_text(sl, "💻 Windows/Linux\nPC (에이전트)", 3.25, 1.78, 2.3, 0.65,
         size=12, color=C_WHITE, align=PP_ALIGN.CENTER)

add_rect(sl, 6.0,  1.75, 2.4, 0.7, fill=C_BLUE)
add_text(sl, "🔧 관리자\n브라우저", 6.05, 1.78, 2.3, 0.65,
         size=12, color=C_WHITE, align=PP_ALIGN.CENTER)

# 화살표 텍스트
add_text(sl, "RADIUS\n802.1x", 0.6, 2.55, 2.0, 0.5, size=10, color=C_LGRAY, align=PP_ALIGN.CENTER)
add_text(sl, "gRPC", 3.55, 2.55, 1.7, 0.3, size=10, color=C_LGRAY, align=PP_ALIGN.CENTER)
add_text(sl, "HTTPS", 6.25, 2.55, 1.9, 0.3, size=10, color=C_LGRAY, align=PP_ALIGN.CENTER)

# 서비스 레이어
services = [
    ("aaa\n:8080/:1812/:1813", C_CYAN,   0.4,  3.1),
    ("agent-gateway\n:50051 (gRPC)",    C_GREEN, 3.1,  3.1),
    ("api-gateway\n:8000",             C_ORANGE, 5.8,  3.1),
    ("admin-console\n:3000",           C_YELLOW, 8.5,  3.1),
]
for label, color, x, y in services:
    add_rect(sl, x, y, 2.5, 0.85, fill=C_ACCENT)
    add_rect(sl, x, y, 2.5, 0.12, fill=color)
    add_text(sl, label, x + 0.1, y + 0.14, 2.3, 0.7,
             size=12, color=C_WHITE, align=PP_ALIGN.CENTER)

# 가운데: policy-manager (핵심)
add_rect(sl, 4.4, 4.2, 4.5, 0.95, fill=C_BLUE)
add_text(sl, "🎯 policy-manager  :8001\nPostgreSQL · Redis · Audit Log", 4.5, 4.22, 4.3, 0.9,
         size=13, bold=True, color=C_WHITE, align=PP_ALIGN.CENTER)

# NATS
add_rect(sl, 0.4, 4.2, 3.7, 0.95, fill=RGBColor(0x2D, 0x2D, 0x44))
add_text(sl, "📨 NATS 이벤트 버스\nnac.events.* / nac.commands.*", 0.5, 4.22, 3.5, 0.9,
         size=12, color=C_CYAN, align=PP_ALIGN.CENTER)

# 하단: sensor / enforcement / dhcp
bottom = [
    ("sensor\nDaemonSet", C_CYAN,   0.4,  5.45),
    ("enforcement\nDaemonSet",     C_RED,    3.1,  5.45),
    ("dhcp\nDaemonSet",            C_GREEN,  5.8,  5.45),
    ("endpoint-agent\n(PC 설치)",   C_LGRAY,  8.5,  5.45),
]
for label, color, x, y in bottom:
    add_rect(sl, x, y, 2.5, 0.8, fill=C_ACCENT)
    add_rect(sl, x, y, 0.1, 0.8, fill=color)
    add_text(sl, label, x + 0.2, y + 0.1, 2.2, 0.65,
             size=12, color=C_WHITE, align=PP_ALIGN.CENTER)

# 하단 인프라
add_rect(sl, 0.4, 6.5, 12.5, 0.65, fill=RGBColor(0x0A, 0x1A, 0x3A))
add_text(sl, "공통 인프라:  PostgreSQL :5432   Redis :6379   NATS :4222",
         0.6, 6.55, 12.1, 0.55,
         size=13, color=C_LGRAY, align=PP_ALIGN.CENTER)

note(sl, """[아키텍처 개요 — 약 3분]

이것이 LEntropy NAC 플랫폼의 전체 아키텍처입니다.

크게 세 층으로 구성됩니다.

상단은 외부 접점입니다. Wi-Fi/스위치는 RADIUS로, PC 에이전트는 gRPC로, 관리자 브라우저는 HTTPS로 플랫폼에 연결됩니다.

중간은 서비스 레이어입니다. aaa 서비스가 RADIUS 인증을 담당하고, agent-gateway가 에이전트와 gRPC 통신을 합니다. api-gateway는 JWT 인증 후 policy-manager로 요청을 프록시합니다. policy-manager가 핵심 엔진으로 모든 정책 결정을 내립니다.

하단은 네트워크 레벨 서비스입니다. sensor가 패킷을 감청하고, enforcement가 ARP 스푸핑으로 차단하며, dhcp가 IP를 할당합니다.

이 모든 서비스가 NATS 이벤트 버스를 통해 비동기적으로 통신합니다.""")

# ══════════════════════════════════════════════════════════════════════════════
# SLIDE 10 — 기술 스택
# ══════════════════════════════════════════════════════════════════════════════
sl = prs.slides.add_slide(BLANK)
bg(sl)
slide_header(sl, "기술 스택", "선택 이유와 역할", "10")

stacks = [
    ("⚙️  Backend — Rust", C_ORANGE,
     "• Axum 0.8: 비동기 HTTP 프레임워크\n• tonic 0.12: gRPC 서버/클라이언트\n• sqlx 0.8: 비동기 PostgreSQL (컴파일 타임 SQL 검증)\n• async-nats: NATS 이벤트 발행/구독\n• pnet 0.35: raw socket 패킷 처리\n선택 이유: 시스템 프로그래밍 수준의 성능 + 메모리 안전성"),
    ("🌐  Frontend — React/TypeScript", C_CYAN,
     "• React 18 + Vite: 빠른 빌드 환경\n• TypeScript 5.6: 타입 안전성\n• Tailwind CSS: 빠른 UI 스타일링\n• Recharts: 통계 차트\n• Axios: API 통신 + JWT 토큰 관리\n선택 이유: 생산성 높은 SPA + 타입 검증"),
    ("🔌  Protocol", C_GREEN,
     "• RADIUS RFC 2865/2866: 802.1x 표준 인증\n• Protocol Buffers + gRPC: 에이전트 통신\n• DHCP RFC 2131: IP 주소 관리\n• JWT (HS256): API 인증\n• ARP: L2 레벨 네트워크 제어"),
    ("☁️  인프라 & 배포", C_BLUE,
     "• Docker Compose: 로컬 개발 환경\n• Kubernetes + Helm: 프로덕션 배포\n• DaemonSet: 네트워크 서비스 (sensor/enforcement)\n• PostgreSQL 16: 단말/정책 데이터\n• Redis 7: 캐시/세션\n• NATS 2.10 JetStream: 이벤트 스트리밍"),
]

for i, (title, color, body) in enumerate(stacks):
    row = i // 2
    col = i % 2
    x = 0.4 + col * 6.45
    y = 1.75 + row * 2.7
    add_rect(sl, x, y, 6.2, 2.5, fill=C_ACCENT)
    add_rect(sl, x, y, 6.2, 0.5, fill=color)
    add_text(sl, title, x + 0.15, y + 0.04, 5.9, 0.44,
             size=15, bold=True, color=C_DARK)
    add_text(sl, body, x + 0.15, y + 0.56, 5.9, 1.87,
             size=12, color=C_WHITE)

note(sl, """[기술 스택 — 약 2분]

백엔드는 Rust로 작성되었습니다. Rust를 선택한 이유는 네트워크 패킷 처리, ARP 스푸핑 같은 시스템 레벨 작업에 C 수준의 성능이 필요하면서도, 메모리 안전성을 컴파일러가 보장해주기 때문입니다.

프론트엔드는 React와 TypeScript로 개발했습니다. 관리자가 실시간으로 단말 상태를 모니터링하고 정책을 변경할 수 있는 SPA입니다.

프로토콜은 업계 표준을 따릅니다. 802.1x RADIUS, gRPC, DHCP 모두 RFC 표준 구현입니다.

배포는 로컬 개발 환경은 Docker Compose, 프로덕션은 Kubernetes Helm 차트로 패키징되어 있습니다.""")

# ══════════════════════════════════════════════════════════════════════════════
# SLIDE 11 — 구현 현황 (컴포넌트별)
# ══════════════════════════════════════════════════════════════════════════════
sl = prs.slides.add_slide(BLANK)
bg(sl)
slide_header(sl, "구현 현황", "컴포넌트별 완성도", "11")

components = [
    ("policy-manager",  "핵심 정책 엔진 + REST API + DB",     "완료", C_GREEN),
    ("sensor",          "ARP/DHCP 패킷 감청 + NATS 발행",      "완료", C_GREEN),
    ("enforcement",     "ARP 스푸핑 기반 L2 차단",             "완료", C_GREEN),
    ("aaa",             "RADIUS Auth/Acct + Captive Portal",   "완료", C_GREEN),
    ("agent-gateway",   "gRPC 수신 + policy-manager 연동",     "완료", C_GREEN),
    ("api-gateway",     "JWT 인증 + REST 프록시",               "완료", C_GREEN),
    ("endpoint-agent",  "Win/Linux 에이전트 + 컴플라이언스 검사","완료", C_GREEN),
    ("dhcp",            "DHCPv4 서버 + MAC 고정 할당",          "완료", C_GREEN),
    ("admin-console",   "React 관리 UI + 대시보드/정책/감사로그","완료", C_GREEN),
    ("Helm Chart",      "Kubernetes 전체 스택 배포",            "완료", C_GREEN),
    ("EAP-TLS/PEAP",    "802.1x 전체 핸드셰이크",               "구조체 완성\n(인증서 연동 필요)", C_ORANGE),
    ("LDAP 연동",        "AD 계정 실제 연동",                    "Mock 구현\n(설정으로 활성화)", C_ORANGE),
]

# 헤더
add_rect(sl, 0.4, 1.72, 5.5, 0.38, fill=C_BLUE)
add_text(sl, "컴포넌트", 0.55, 1.74, 5.3, 0.34,
         size=13, bold=True, color=C_WHITE)
add_rect(sl, 5.95, 1.72, 4.0, 0.38, fill=C_BLUE)
add_text(sl, "역할", 6.1, 1.74, 3.8, 0.34,
         size=13, bold=True, color=C_WHITE)
add_rect(sl, 10.0, 1.72, 2.85, 0.38, fill=C_BLUE)
add_text(sl, "상태", 10.15, 1.74, 2.65, 0.34,
         size=13, bold=True, color=C_WHITE)

for i, (name, role, status, color) in enumerate(components):
    y = 2.15 + i * 0.44
    bg_c = C_ACCENT if i % 2 == 0 else RGBColor(0x12, 0x1A, 0x30)
    add_rect(sl, 0.4, y, 5.5, 0.42, fill=bg_c)
    add_rect(sl, 5.95, y, 4.0, 0.42, fill=bg_c)
    add_rect(sl, 10.0, y, 2.85, 0.42, fill=bg_c)
    add_text(sl, name, 0.55, y + 0.04, 5.3, 0.36,
             size=12, bold=True, color=C_CYAN)
    add_text(sl, role, 6.1, y + 0.04, 3.8, 0.36,
             size=11, color=C_WHITE)
    add_text(sl, status, 10.15, y + 0.04, 2.65, 0.36,
             size=11, bold=True, color=color)

note(sl, """[구현 현황 — 약 2분]

총 10개 서비스와 2개 Rust 크레이트 라이브러리가 구현되어 있습니다.
핵심 기능은 모두 완료 상태입니다.

완료된 항목은 그린으로 표시됩니다. policy-manager부터 admin-console까지 전체 파이프라인이 동작합니다.

오렌지로 표시된 항목은 부분 구현입니다.
EAP-TLS/PEAP는 802.1x의 전체 TLS 핸드셰이크 구조는 작성되었지만, 실제 인증서를 연동하려면 추가 설정이 필요합니다.
LDAP 연동은 Mock 모드로 구현되어 있어, 환경변수에 LDAP_URL을 설정하면 실제 AD와 연동됩니다.""")

# ══════════════════════════════════════════════════════════════════════════════
# SLIDE 12 — 주요 기능 데모 시나리오
# ══════════════════════════════════════════════════════════════════════════════
sl = prs.slides.add_slide(BLANK)
bg(sl)
slide_header(sl, "데모 시나리오", "Ubuntu 서버 + Windows 10 클라이언트", "12")

steps_demo = [
    ("STEP 1", C_CYAN,   "서버 기동",
     "docker compose up -d\n8개 서비스 자동 시작 (PostgreSQL · Redis · NATS · 앱 서비스)"),
    ("STEP 2", C_BLUE,   "Admin Console 접속",
     "브라우저 → http://<서버IP>:3000\nadmin / changeme 로그인 → JWT 발급 → 대시보드 이동"),
    ("STEP 3", C_GREEN,  "Windows 에이전트 실행",
     "endpoint-agent.exe 실행 (PowerShell)\n30초 후 Endpoints 목록에 DESKTOP-xxx 자동 등록"),
    ("STEP 4", C_ORANGE, "단말 제어",
     "Allow → Block → Quarantine 버튼 클릭\n감사 로그에 모든 변경 이력 자동 기록"),
    ("STEP 5", C_RED,    "RADIUS 인증 테스트",
     "radtest admin changeme localhost 0 radius-shared-secret\nAccess-Accept 응답 확인"),
]
for i, (step, color, title, body) in enumerate(steps_demo):
    y = 1.73 + i * 1.0
    add_rect(sl, 0.4, y, 1.0, 0.85, fill=color)
    add_text(sl, step, 0.42, y + 0.12, 0.96, 0.6,
             size=12, bold=True, color=C_DARK, align=PP_ALIGN.CENTER)
    add_rect(sl, 1.45, y, 11.4, 0.85, fill=C_ACCENT)
    add_text(sl, title, 1.6, y + 0.04, 3.5, 0.38,
             size=14, bold=True, color=color)
    add_text(sl, body, 1.6, y + 0.42, 11.1, 0.42,
             size=12, color=C_LGRAY)

note(sl, """[데모 시나리오 — 약 4분]

실제 테스트는 이 5단계로 진행됩니다.

1단계: docker compose up -d 명령 한 번으로 8개 서비스가 자동으로 시작됩니다.
PostgreSQL, Redis, NATS 인프라가 먼저 기동되고, 헬스체크가 통과되면 앱 서비스들이 순차적으로 시작됩니다.

2단계: 브라우저에서 Admin Console에 접속합니다. 로그인하면 JWT 토큰이 발급되어 이후 모든 API 호출에 자동으로 포함됩니다.

3단계: Windows PC에서 endpoint-agent.exe를 실행합니다. 30초 후 서버의 Endpoints 목록에 해당 PC가 자동으로 등록됩니다.

4단계: 관리자가 단말을 허용, 차단, 격리 상태로 변경할 수 있습니다. 모든 조작은 감사 로그에 자동 기록됩니다.

5단계: radtest 명령으로 RADIUS 인증을 테스트합니다. Access-Accept 응답이 오면 정상입니다.""")

# ══════════════════════════════════════════════════════════════════════════════
# SLIDE 13 — 보안 고려사항
# ══════════════════════════════════════════════════════════════════════════════
sl = prs.slides.add_slide(BLANK)
bg(sl)
slide_header(sl, "보안 고려사항", "프로덕션 적용 전 필수 체크", "13")

checks = [
    (C_RED,    "🔑 JWT_SECRET", "기본값 'change-me...' → 최소 32자 무작위 문자열 교체 필수"),
    (C_RED,    "🔐 RADIUS_SECRET", "기본값 'radius-shared-secret' → 강력한 시크릿으로 교체"),
    (C_RED,    "🔒 ADMIN_PASS", "기본값 'changeme' → 즉시 변경 (브루트포스 공격 대상)"),
    (C_ORANGE, "🗄️ DB 비밀번호", "PostgreSQL nac_dev_password → 프로덕션 강력한 비밀번호"),
    (C_ORANGE, "🌐 TLS 인증서", "API Gateway / Admin Console에 HTTPS 적용 (cert-manager 권장)"),
    (C_ORANGE, "📡 RADIUS UDP", "1812/1813 포트를 NAS 장비 IP로만 방화벽 제한"),
    (C_CYAN,   "🏗️ 권한 격리", "sensor/enforcement는 NET_RAW 권한 필요 → 전용 노드에 격리"),
    (C_CYAN,   "📋 LDAP/AD 연동", "LDAP_URL 환경변수 설정으로 실제 AD 계정 인증 활성화"),
]
for i, (color, title, desc) in enumerate(checks):
    row = i // 2
    col = i % 2
    x = 0.4 + col * 6.45
    y = 1.75 + row * 1.28
    add_rect(sl, x, y, 6.2, 1.18, fill=C_ACCENT)
    add_rect(sl, x, y, 0.12, 1.18, fill=color)
    add_text(sl, title, x + 0.25, y + 0.08, 5.8, 0.38,
             size=14, bold=True, color=color)
    add_text(sl, desc, x + 0.25, y + 0.48, 5.8, 0.65,
             size=12, color=C_LGRAY)

note(sl, """[보안 고려사항 — 약 2분]

현재 코드는 개발 편의를 위해 기본값이 설정되어 있습니다.
프로덕션 환경에 배포하기 전에 반드시 변경해야 할 항목들입니다.

빨간색으로 표시된 세 항목은 반드시 변경해야 합니다.
JWT 시크릿, RADIUS 시크릿, 관리자 비밀번호는 기본값으로 두면 즉시 공격에 노출됩니다.

주황색 항목은 운영 환경 설정입니다.
PostgreSQL 비밀번호 강화, TLS 인증서 적용, RADIUS 포트 방화벽 제한이 여기에 해당합니다.

시안색 항목은 아키텍처 관련 고려사항입니다.
sensor와 enforcement는 raw socket을 사용하므로 NET_RAW 권한이 필요하고, 보안상 전용 노드에 격리하는 것이 권장됩니다.""")

# ══════════════════════════════════════════════════════════════════════════════
# SLIDE 14 — 향후 로드맵
# ══════════════════════════════════════════════════════════════════════════════
sl = prs.slides.add_slide(BLANK)
bg(sl)
slide_header(sl, "향후 로드맵", "단계별 발전 계획", "14")

phases = [
    ("Phase 1\n(1~2개월)", C_CYAN, [
        "EAP-TLS/PEAP 완전 구현 (인증서 연동)",
        "LDAP/AD 실제 연동 검증",
        "Windows Defender 예외 자동화",
        "에이전트 Windows 서비스 설치 패키지",
    ]),
    ("Phase 2\n(3~4개월)", C_GREEN, [
        "VLAN 동적 할당 (802.1q 태깅)",
        "위협 인텔리전스 연동 (CVE 피드)",
        "macOS 에이전트 지원 (Apple Silicon)",
        "알림 연동 (Slack / 이메일 / SMS)",
    ]),
    ("Phase 3\n(5~6개월)", C_ORANGE, [
        "AI 기반 이상 행위 탐지 (ML 모델)",
        "멀티 테넌트 관리 (MSP 지원)",
        "OpenTelemetry 분산 추적",
        "SOC/SIEM 연동 (Splunk / ELK)",
    ]),
]

for i, (phase, color, items) in enumerate(phases):
    x = 0.4 + i * 4.3
    add_rect(sl, x, 1.7, 4.05, 5.2, fill=C_ACCENT)
    add_rect(sl, x, 1.7, 4.05, 0.65, fill=color)
    add_text(sl, phase, x + 0.15, 1.73, 3.75, 0.6,
             size=16, bold=True, color=C_DARK, align=PP_ALIGN.CENTER)
    ty = 2.45
    for item in items:
        add_text(sl, "  ▸  " + item, x + 0.1, ty, 3.85, 0.55,
                 size=13, color=C_WHITE)
        ty += 0.62

note(sl, """[향후 로드맵 — 약 2분]

개발 로드맵은 3단계로 구성됩니다.

Phase 1은 현재 부분 구현된 기능을 완성하는 단계입니다. EAP-TLS 완전 구현과 LDAP 연동 검증, 그리고 에이전트를 Windows 서비스로 설치할 수 있는 패키지를 만들 계획입니다.

Phase 2는 엔터프라이즈 기능 확장입니다. VLAN 동적 할당으로 격리 수준을 높이고, CVE 피드와 연동하여 패치되지 않은 취약점을 가진 장치를 자동으로 탐지합니다. macOS 에이전트도 지원할 예정입니다.

Phase 3는 지능화 단계입니다. 기계학습 모델로 네트워크 이상 행위를 탐지하고, SOC/SIEM 시스템과 연동하여 기업 보안 운영 센터에 통합합니다.""")

# ══════════════════════════════════════════════════════════════════════════════
# SLIDE 15 — 핵심 가치 요약
# ══════════════════════════════════════════════════════════════════════════════
sl = prs.slides.add_slide(BLANK)
bg(sl)
slide_header(sl, "핵심 가치 요약", "LEntropy NAC Platform이 제공하는 것", "15")

values = [
    ("🚀 즉시 배포 가능",
     "docker compose up -d\n한 명령으로 전체 스택 기동\n추가 설정 없이 즉시 테스트"),
    ("🔒 이중 제어 방식",
     "에이전트리스 + 에이전트 동시 지원\n설치 불가 장치도 ARP 스푸핑으로 차단\n두 방식의 정보를 통합 관리"),
    ("📊 완전한 가시성",
     "모든 접속 이력 자동 감사 로그\n실시간 단말 현황 대시보드\n정책 변경 이력 추적"),
    ("⚡ 고성능 Rust",
     "C 수준 성능 + 메모리 안전성\n수만 단말 동시 처리 가능\n최소 리소스로 최대 처리량"),
    ("☁️ 클라우드 네이티브",
     "Kubernetes Helm 차트 제공\nDaemonSet / Deployment 분리\n수평 확장(Scale-out) 지원"),
    ("🧩 표준 프로토콜",
     "RADIUS RFC 2865 준수\ngRPC / Protocol Buffers\n기존 NAS 장비와 호환"),
]
for i, (title, body) in enumerate(values):
    row = i // 3
    col = i % 3
    x = 0.4 + col * 4.3
    y = 1.75 + row * 2.55
    add_rect(sl, x, y, 4.05, 2.35, fill=C_ACCENT)
    add_text(sl, title, x + 0.15, y + 0.12, 3.75, 0.5,
             size=15, bold=True, color=C_CYAN)
    add_rect(sl, x + 0.1, y + 0.62, 3.85, 0.04, fill=C_BLUE)
    add_text(sl, body, x + 0.15, y + 0.74, 3.75, 1.52,
             size=13, color=C_WHITE)

note(sl, """[핵심 가치 요약 — 약 2분]

LEntropy NAC Platform의 핵심 가치 여섯 가지를 정리하겠습니다.

첫째, 즉시 배포 가능합니다. docker compose up 명령 하나로 전체 스택이 올라옵니다.
둘째, 이중 제어 방식입니다. 에이전트 설치 여부와 관계없이 모든 장치를 제어할 수 있습니다.
셋째, 완전한 가시성입니다. 누가 언제 어떤 장치로 접속했는지 모든 이력이 자동 기록됩니다.
넷째, Rust 기반의 고성능입니다. 수만 개의 단말을 최소 리소스로 처리합니다.
다섯째, 클라우드 네이티브입니다. Kubernetes로 어디서든 배포할 수 있습니다.
여섯째, 표준 프로토콜을 사용합니다. 기존 Wi-Fi AP나 스위치와 바로 연동됩니다.""")

# ══════════════════════════════════════════════════════════════════════════════
# SLIDE 16 — Q&A
# ══════════════════════════════════════════════════════════════════════════════
sl = prs.slides.add_slide(BLANK)
bg(sl)

add_rect(sl, 0, 0, 4.5, 7.5, fill=C_BLUE)
add_rect(sl, 4.5, 0, 0.08, 7.5, fill=C_CYAN)
add_text(sl, "Q&A", 0.3, 2.5, 3.9, 1.5,
         size=80, bold=True, color=C_WHITE, align=PP_ALIGN.CENTER)
add_text(sl, "질문과 답변", 0.3, 4.1, 3.9, 0.55,
         size=20, color=C_CYAN, align=PP_ALIGN.CENTER)

add_text(sl, "감사합니다", 5.0, 1.8, 8.0, 1.0,
         size=44, bold=True, color=C_WHITE)
add_rect(sl, 5.0, 2.85, 7.8, 0.06, fill=C_CYAN)

contacts = [
    "🔗 GitHub:  github.com/LEntropy/LEntropy",
    "📦 Branch:  claude/setup-dev-environment-5cxDF",
    "📋 Docs:    docs/deployment.md",
    "🧪 테스트:  docs/test-guide.md",
    "🚀 기동:    docker compose up -d",
]
ty = 3.1
for c in contacts:
    add_text(sl, c, 5.0, ty, 8.1, 0.48, size=15, color=C_LGRAY)
    ty += 0.52

add_rect(sl, 5.0, 6.2, 7.8, 0.65, fill=C_ACCENT)
add_text(sl, "LEntropy NAC Platform  v0.1  |  Rust + React + Kubernetes",
         5.1, 6.28, 7.6, 0.48,
         size=13, color=C_CYAN, align=PP_ALIGN.CENTER)

note(sl, """[Q&A — 약 5분]

발표를 들어주셔서 감사합니다.

지금까지 NAC의 개념, 동작 원리, 산업별 활용 방안, 그리고 LEntropy NAC 플랫폼의 실제 구현 내용을 설명드렸습니다.

주요 내용을 정리하면:
- NAC는 네트워크의 모든 장치를 식별·인증·제어하는 보안 프레임워크입니다.
- 에이전트리스와 에이전트 방식을 모두 지원합니다.
- Rust로 개발된 10개 서비스가 NATS 이벤트 버스로 연결됩니다.
- Docker Compose로 즉시 배포, Kubernetes로 프로덕션 운영이 가능합니다.

궁금하신 점이 있으시면 질문해 주시기 바랍니다.

[일반적으로 받는 질문 예시]
Q: ARP 스푸핑이 스위치 포트 보안(Dynamic ARP Inspection)에 의해 막히지 않나요?
A: 맞습니다. 엔터프라이즈 스위치에서 DAI가 활성화되어 있으면 ARP 스푸핑이 차단됩니다. 이 경우 VLAN 변경이나 802.1x 포트 비활성화를 사용해야 합니다. 저희 플랫폼은 향후 VLAN 동적 제어를 Phase 2 로드맵에 포함하고 있습니다.

Q: endpoint-agent가 삭제되면 차단을 우회할 수 있지 않나요?
A: 에이전트 기반 제어는 컴플라이언스 검사 용도가 주 목적입니다. 실제 네트워크 차단은 에이전트와 무관하게 enforcement 서비스가 ARP 스푸핑으로 수행하므로, 에이전트를 삭제해도 네트워크 레벨 차단은 계속 동작합니다.""")

# ── 저장 ──────────────────────────────────────────────────────────────────────
out = "/home/user/LEntropy/docs/NAC_플랫폼_발표자료.pptx"
prs.save(out)
print(f"저장 완료: {out}")
print(f"슬라이드 수: {len(prs.slides)}")
