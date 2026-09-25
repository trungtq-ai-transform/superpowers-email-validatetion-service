# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Toàn bộ hướng dẫn của dự án — lệnh, kiến trúc, Nên / Không nên — nằm trong `AGENTS.md` để mọi
coding agent dùng chung một nguồn:

@AGENTS.md

## Riêng cho Claude Code

- Tài liệu thiết kế theo quy trình superpowers: spec ở `docs/superpowers/specs/`, plan triển
  khai ở `docs/superpowers/plans/`. Đọc spec trước khi thay đổi hành vi; khi code và plan mâu
  thuẫn, spec là căn cứ cuối cùng.
- `.superpowers/` là thư mục nháp cho subagent-driven development (đã được git bỏ qua); không
  bao giờ commit nó.
- Commit message kết thúc bằng trailer `Co-Authored-By:` của model đã viết thay đổi.
