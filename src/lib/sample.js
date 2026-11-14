// A small, deliberately plain sample set: five real-world-shaped findings so the
// desk is never empty on first load, and every UI state (overdue, due-soon, unknown
// EPSS, closed, invalid-but-importable) is visible at once.

export function sampleVulns(today = new Date()) {
  const daysAgo = (n) => {
    const d = new Date(Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate()));
    d.setUTCDate(d.getUTCDate() - n);
    return d.toISOString().slice(0, 10);
  };

  return [
    {
      id: 'sample-1',
      title: '内部 API 网关的 JWT 校验绕过',
      cve: 'CVE-2026-31842',
      vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N/E:A',
      epss: 0.943,
      assetImportance: 5,
      assetName: '支付网关',
      discoveredAt: daysAgo(12),
      status: 'open',
      owner: '安全组',
      notes: '已确认存在公开利用代码，WAF 规则仅能部分缓解。',
      source: 'scanner',
    },
    {
      id: 'sample-2',
      title: 'OpenSSL 证书链校验缺陷（可致中间人）',
      cve: 'CVE-2026-22719',
      vector: 'CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/E:P',
      epss: 0.31,
      assetImportance: 4,
      assetName: '对外门户',
      discoveredAt: daysAgo(5),
      status: 'in_progress',
      owner: '基础架构',
      notes: '等待厂商补丁，已在边界启用证书固定。',
      source: 'vendor',
    },
    {
      id: 'sample-3',
      title: '日志组件路径穿越导致任意文件读取',
      cve: 'CVE-2026-10233',
      vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/E:U/CR:H/IR:L/AR:L',
      epss: 0.08,
      assetImportance: 3,
      assetName: '内部报表服务',
      discoveredAt: daysAgo(20),
      status: 'open',
      owner: '数据平台',
      notes: '仅内网可达，但可读取配置中的凭据。',
      source: 'scanner',
    },
    {
      id: 'sample-4',
      title: '前端依赖库原型污染（无可利用路径）',
      cve: 'CVE-2026-40017',
      vector: 'CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N/E:U',
      epss: null,
      assetImportance: 2,
      assetName: '营销站点',
      discoveredAt: daysAgo(40),
      status: 'open',
      owner: '前端组',
      notes: '暂无 EPSS 数据，等待下一轮威胁情报同步。',
      source: 'sca',
    },
    {
      id: 'sample-5',
      title: '运维脚本硬编码数据库口令',
      cve: '',
      vector: 'CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U/CR:H/IR:H/AR:M',
      epss: null,
      assetImportance: 4,
      assetName: 'CI/CD 平台',
      discoveredAt: daysAgo(45),
      status: 'resolved',
      owner: 'SRE',
      notes: '已迁移到密钥管理服务并轮换口令。',
      source: 'audit',
    },
  ];
}
