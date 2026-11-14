#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { open } from 'node:fs/promises';
import zlib from 'node:zlib';

const MiB = 1024 * 1024;
const maxCompressed = 64 * MiB;
const maxDecoded = 128 * MiB;

class InspectionError extends Error {}

function fail(message) {
  throw new InspectionError(message);
}

const usageHelp = '用法：node dsh-session-inspect.mjs <快照文件> [--json] [--cold <冷档文件> [--cold-sha256 <已登记的摘要>]]';

function parseArgs(args) {
  const options = {};
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--json' && !options.json) {
      options.json = true;
    } else if (arg === '--cold' || arg === '--cold-sha256') {
      const key = arg === '--cold' ? 'cold' : 'expectedHash';
      const value = args[++i];
      if (options[key] || !value || value.startsWith('-')) fail('选项重复或缺少参数。');
      options[key] = value;
    } else if (!arg.startsWith('-') && !options.file) {
      options.file = arg;
    } else {
      fail('参数不受支持或重复。请指定单个快照文件。');
    }
  }
  if (!options.file) fail(usageHelp);
  if (options.expectedHash && (!options.cold || !/^[a-f\d]{64}$/i.test(options.expectedHash))) {
    fail('冷档摘要需要配合 --cold，且必须是 64 位十六进制 SHA-256。');
  }
  return options;
}

async function readSnapshot(path, label) {
  let handle;
  try {
    handle = await open(path, 'r');
    const before = await handle.stat({ bigint: true });
    if (!before.isFile()) fail(label + '必须是一个文件。');
    if (before.size < 1n || before.size > BigInt(maxCompressed)) {
      fail(label + '为空或超过 64 MiB。');
    }
    const bytes = Buffer.alloc(Number(before.size));
    let offset = 0;
    while (offset < bytes.length) {
      const { bytesRead } = await handle.read(bytes, offset, bytes.length - offset, offset);
      if (!bytesRead) fail(label + '读取期间发生变化，请使用离线快照。');
      offset += bytesRead;
    }
    const after = await handle.stat({ bigint: true });
    if (before.size !== after.size || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs) {
      fail(label + '读取期间发生变化，请使用离线快照。');
    }
    return bytes;
  } catch (error) {
    if (error instanceof InspectionError) throw error;
    fail(label + '无法读取，请检查文件与权限。');
  } finally {
    await handle?.close();
  }
}

async function decode(bytes, label) {
  if (bytes.length < 4 || bytes.readUInt32LE() !== 0xfd2fb528) fail(label + '缺少 Zstd 帧头。');
  const decoder = zlib.createZstdDecompress();
  const chunks = [];
  let size = 0;
  decoder.end(bytes);
  try {
    for await (const chunk of decoder) {
      size += chunk.length;
      if (size > maxDecoded) fail(label + '解压后超过 128 MiB。');
      chunks.push(chunk);
    }
    if (decoder.bytesWritten !== bytes.length) fail(label + '含未解码的尾部数据。');
    return new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks, size));
  } catch (error) {
    if (error instanceof InspectionError) throw error;
    fail(label + '解压失败或含无效 UTF-8。');
  } finally {
    decoder.destroy();
  }
}

const isCount = value => Number.isSafeInteger(value) && value >= 0;

function parseLine(line, lineNumber, label) {
  let record;
  try {
    record = JSON.parse(line);
  } catch {
    fail(label + '第 ' + lineNumber + ' 行不是有效 JSON。');
  }
  if (!record || typeof record !== 'object' || Array.isArray(record)) {
    fail(label + '第 ' + lineNumber + ' 行需要 JSON 对象。');
  }
  return record;
}

function measureUsage(data) {
  const raw = data?.usage;
  if (!isCount(raw?.totalTokens)) return null;
  return {
    totalTokens: raw.totalTokens,
    inputTokens: isCount(raw.inputTokens) ? raw.inputTokens : null,
    cacheReadTokens: isCount(raw.cacheReadTokens) ? raw.cacheReadTokens : null,
    cacheWriteTokens: isCount(raw.cacheWriteTokens) ? raw.cacheWriteTokens : null,
    outputTokens: isCount(raw.outputTokens) ? raw.outputTokens : null,
  };
}

function inspect(text, label) {
  const lines = text.split('\n');
  if (lines.at(-1) === '') lines.pop();
  const header = parseLine(lines[0], 1, label);
  if (header.version !== 4 || typeof header.id !== 'string' || !header.id.trim() || !isCount(header.createdAt) || !header.createdAt) {
    fail(label + '头部缺少有效的 v4 版本、会话 ID 或创建时间。');
  }
  const usage = [];
  const compactions = new Map();
  for (let i = 1; i < lines.length; i++) {
    const { seq, type, data } = parseLine(lines[i], i + 1, label);
    if (!isCount(seq) || seq !== i - 1 || typeof type !== 'string' || !type.trim()) {
      fail(label + '第 ' + (i + 1) + ' 行的事件类型或序号无效。');
    }
    if (type === 'assistant/message') {
      const sample = measureUsage(data);
      if (sample) usage.push({ seq, ...sample });
    }
    const stage = type.slice('compaction/'.length);
    if (!type.startsWith('compaction/') || !['start', 'summary', 'end'].includes(stage)) continue;
    const id = data?.compactionId;
    if (typeof id !== 'string' || !id.trim()) fail(label + '第 ' + (i + 1) + ' 行缺压缩关联 ID。');
    const group = compactions.get(id) ?? {};
    if (Object.hasOwn(group, stage)) fail(label + '第 ' + (i + 1) + ' 行的压缩阶段重复。');
    group[stage] = seq;
    if (stage === 'summary') {
      group.shadowedEvents = Array.isArray(data.shadowedSeqs) ? data.shadowedSeqs.length : null;
      group.summaryUsage = measureUsage(data);
    }
    compactions.set(id, group);
  }
  return { header, events: lines.length - 1, usage, compactions: [...compactions.values()] };
}

function summarize(stats) {
  const { events, usage, compactions } = stats;
  const latest = compactions.reduce((last, group) => {
    const lastSeq = item => Math.max(item.start ?? -1, item.summary ?? -1, item.end ?? -1);
    return !last || lastSeq(group) > lastSeq(last) ? group : last;
  }, null);
  let comparison = null;
  if (latest && latest.start < latest.summary && latest.summary < latest.end) {
    const before = usage.findLast(sample => sample.seq < latest.start) ?? null;
    const after = usage.find(sample => sample.seq > latest.end) ?? null;
    comparison = {
      before,
      after,
      reductionPercent: before?.totalTokens > 0 && after
        ? Number(((1 - after.totalTokens / before.totalTokens) * 100).toFixed(2))
        : null,
    };
  }
  return {
    formatVersion: 4,
    events,
    usageSamples: usage.length,
    latestUsage: usage.at(-1) ?? null,
    compactionCount: compactions.length,
    latestCompaction: latest ? { ...latest, complete: comparison !== null } : null,
    comparison,
  };
}

function show(result) {
  const lines = ['DSH 会话只读体检', '快照字节数  ' + result.bytes, '序号连续的事件  ' + result.events,
    '压缩记录  ' + result.compactionCount, '最新助手样本 totalTokens  ' + (result.latestUsage?.totalTokens ?? '无')];
  if (result.latestCompaction) {
    const { start, summary, end, complete, shadowedEvents, summaryUsage } = result.latestCompaction;
    lines.push('最近压缩 start / summary / end  ' + [start, summary, end].map(value => value ?? '缺失').join(' / '));
    if (shadowedEvents !== null && shadowedEvents !== undefined) lines.push('摘要标记的遮蔽事件  ' + shadowedEvents);
    if (summaryUsage) lines.push('生成摘要 totalTokens  ' + summaryUsage.totalTokens);
    if (!complete) lines.push('压缩记录不齐或顺序异常，无法比较。');
  }
  if (result.comparison) {
    const { before, after, reductionPercent } = result.comparison;
    lines.push('压缩前最后 / 压缩后首个助手样本 totalTokens  ' +
      (before?.totalTokens ?? '缺失') + ' / ' + (after?.totalTokens ?? '缺失'));
    if (reductionPercent !== null) lines.push('样本降幅  ' + reductionPercent + '%');
  }
  if (result.cold) {
    lines.push('冷档 ID 和创建时间  ' + (result.cold.sameIdentity ? '相符' : '不符'));
    lines.push('冷档 SHA-256  ' + (result.cold.expectedSha256Matches === null ? '未提供预登记摘要'
      : result.cold.expectedSha256Matches ? '与预登记摘要相符' : '与预登记摘要不符'));
  }
  return lines.join('\n');
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length === 1 && ['--help', '-h'].includes(args[0])) {
    console.log(usageHelp);
    return;
  }
  const options = parseArgs(args);
  if (typeof zlib.createZstdDecompress !== 'function') fail('需要支持 Zstd 的 Node.js，建议使用 Node.js 24。');
  const bytes = await readSnapshot(options.file, '输入快照');
  const stats = inspect(await decode(bytes, '输入快照'), '输入快照');
  const result = { bytes: bytes.length, ...summarize(stats) };
  if (options.cold) {
    const coldBytes = await readSnapshot(options.cold, '冷档');
    const cold = inspect(await decode(coldBytes, '冷档'), '冷档');
    result.cold = {
      bytes: coldBytes.length,
      sameIdentity: cold.header.id === stats.header.id && cold.header.createdAt === stats.header.createdAt,
      expectedSha256Matches: options.expectedHash
        ? createHash('sha256').update(coldBytes).digest('hex') === options.expectedHash.toLowerCase()
        : null,
    };
    if (!result.cold.sameIdentity || result.cold.expectedSha256Matches === false) process.exitCode = 1;
  }
  console.log(options.json ? JSON.stringify(result, null, 2) : show(result));
}

try {
  await main();
} catch (error) {
  console.error('体检失败：' + (error instanceof InspectionError ? error.message : '读取或解析未完成。'));
  process.exitCode = 1;
}

