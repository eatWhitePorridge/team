// Shared, solid-color Bento tokens. No remote fonts or additional UI framework.
export const uiColors = {
  canvas: '#f4f4f5', surface: '#ffffff', subtle: '#fafafa',
  ink: '#18181b', secondary: '#52525b', border: '#e4e4e7',
  accent: '#d9f99d', accentInk: '#365314', accentSoft: '#f7fee7',
  success: '#166534', successSurface: '#f0fdf4',
  warning: '#92400e', warningSurface: '#fffbeb',
  danger: '#b91c1c', dangerSurface: '#fef2f2',
  info: '#1e40af', infoSurface: '#eff6ff',
} as const;
export const uiFont = '-apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", sans-serif';
export const uiTheme = {
  token: {
    colorPrimary: uiColors.ink, colorLink: uiColors.accentInk, colorLinkHover: '#3f6212',
    colorText: uiColors.ink, colorTextSecondary: uiColors.secondary, colorTextDescription: uiColors.secondary,
    colorTextPlaceholder: '#71717a', colorBgLayout: uiColors.canvas, colorBgContainer: uiColors.surface,
    colorBorder: '#d4d4d8', colorBorderSecondary: uiColors.border,
    colorSuccess: uiColors.success, colorWarning: uiColors.warning, colorError: uiColors.danger, colorInfo: uiColors.info,
    borderRadius: 12, borderRadiusSM: 12, borderRadiusLG: 16, controlHeight: 40, fontSize: 14, fontFamily: uiFont,
    motionEaseInOut: 'ease-out', motionEaseOut: 'ease-out',
  },
  components: {
    Card: { borderRadiusLG: 16, paddingLG: 24 },
    Button: { primaryShadow: 'none', defaultShadow: 'none', fontWeight: 500 },
    Table: { headerBg: uiColors.subtle, headerColor: uiColors.secondary, rowSelectedBg: '#f7fee7', rowSelectedHoverBg: '#ecfccb', cellPaddingBlock: 16, cellPaddingInline: 16 },
    Tabs: { inkBarColor: uiColors.ink, itemSelectedColor: uiColors.ink, itemHoverColor: uiColors.accentInk },
    Segmented: { trackBg: uiColors.canvas, itemSelectedBg: uiColors.ink, itemSelectedColor: '#ffffff' },
    Progress: { defaultColor: uiColors.accentInk, remainingColor: uiColors.border },
    Modal: { borderRadiusLG: 16, paddingContentHorizontalLG: 24 },
  },
};
