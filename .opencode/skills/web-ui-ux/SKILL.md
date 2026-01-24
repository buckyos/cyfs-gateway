name: web-ui-ux
description: "BuckyOS Design System: Industrial precision, RPC-driven data density, and strict token adherence."
content: |
  # BuckyOS Control Panel Design System

  ## <Design_Philosophy>
  **【道】 秩序与克制 (Order & Restraint)**
  BuckyOS 的控制面板不是营销页面，而是**工业级的操作台**。
  - **功能至上 (Function First):** 美学服务于效率。拒绝无意义的动画与装饰。
  - **数据投影 (Data Projection):** UI 仅仅是底层 RPC 数据的直观投影。保持 UI 状态与 RPC 契约的绝对一致。
  - **精准如一 (Precision):** 像素级的对齐，严苛的一致性。

  **【Technique】 Core Vibe**
  - **Tone:** Technical, Robust, Neutral.
  - **Density:** High (Information-dense but readable).
  - **Behavior:** Predictable & Snappy (150-300ms transitions).
  </Design_Philosophy>

  ## <Visual_Law>
  **【术】 视觉法典 (Hard Constraints)**
  Violating these tokens is a compilation error in design.

  ### 1. The Palette (Strict Hex Codes)
  | Role | Color | Hex | Usage |
  | :--- | :--- | :--- | :--- |
  | **Primary** | Teal | `#0f766e` | Main actions, active states, key branding. |
  | **Accent** | Amber | `#f59e0b` | Warnings, highlights, "beta" tags. |
  | **Neutrals** | Slate | `#0f172a` (Ink), `#52606d` (Muted), `#d7e1df` (Border), `#f4f8f7` (Bg-Muted), `#ffffff` (Surface). |
  | **Status** | Semantic | Use standard Error/Success colors aligned with Neutrals. |

  ### 2. Typography (The Voice)
  - **Headings:** `Space Grotesk` (Tech/Industrial feel). Line-height: `1.2`.
  - **Body:** `Work Sans` (Legibility). Line-height: `1.5`.
  - **Scale:** `12px` (Label) / `14px` (Body) / `16px` (Body-L) / `20px` (H3) / `24px` (H2) / `32px` (H1).

  ### 3. Spacing & Shape (The Grid)
  - **Base Unit:** `4px`. All spacing MUST be a multiple of 4 (4, 8, 12, 16, 24, 32).
  - **Radius:** `8px` (Small components) / `12px` (Cards) / `18px` / `24px`.
  - **Shadows:** Soft & Diffuse. Avoid harsh, heavy blurs.

  ### 4. Iconography
  - **Source:** **ONE** SVG set only (e.g., Lucide, Heroicons).
  - **FORBIDDEN:** 🚫 Emoji icons ( unprofessional), Mixed icon sets.
  </Visual_Law>

  ## <Component_Specifications>
  **【术】 组件规约 (Implementation Rules)**

  ### Layout & Responsive
  - **Desktop First:** Max content `1280px`, Sidebar `260px` (Fixed).
  - **Grid Gap:** `16px` (Tight) - `24px` (Relaxed).
  - **Padding:** Desktop `24px` / Mobile `16px`.
  - **Scroll:** **NO** horizontal scroll on page level. Tables must handle internal overflow.

  ### Interaction Mandates
  1.  **Touch Targets:** `>= 44x44px` for ALL clickable elements.
  2.  **State Feedback:** Every interactive element MUST have `:hover`, `:active`, `:focus-visible`, and `:disabled`.
  3.  **Forms:**
      - Label + Input + Helper Text (Stack vertical).
      - Inline Validation (Error message replaces helper text).
  4.  **Loading:** Use **Skeletons** (matching layout), NEVER full-screen spinners.

  ### RPC Alignment (Critical)
  - **Field Matching:** UI labels MUST conceptually match Backend RPC field names (e.g., `user_id` -> "User ID").
  - **Empty States:** Never show a blank box. Explain *why* it's empty + Provide `Next Action`.

  </Component_Specifications>

  ## <Review_Checklist>
  **【道】 慎独 (Self-Correction)**
  Before outputting code, verify:
  1.  [ ] Are fonts `Space Grotesk` / `Work Sans`?
  2.  [ ] Are all touch targets >= 44px?
  3.  [ ] Is the color palette strictly from the Design Tokens?
  4.  [ ] Are there any Emojis? (If yes, destroy them).
  5.  [ ] Does the UI reflect the RPC data structure accurately?