---
name: worldcup-2026-assistant
description: 2026世界杯全站助手 — 覆盖赛前科普、赛中播报、赛后传播的全链路 Skill。功能包括：足球规则速成、2026新赛制解读、48强球队速览、球星档案、世界杯有趣知识、当日赛程播报、小组赛出线形势分析、赛后社交文案生成（朋友圈/公众号/小红书）、比赛亮点回顾、主队应援指南。数据层依赖 football-data Skill 获取实时赛程/比分/积分榜。触发词：世界杯、World Cup、2026、赛程、比分、球队、球星、足球规则、出线、文案、播报、看球、球迷。
---

# 2026 世界杯全站助手

从「看懂」→「看爽」→「聊得上」→「玩起来」，覆盖伪球迷到真球迷的全链路。

## 数据依赖

实时赛程、比分、积分榜、球员数据通过 `football-data` Skill 获取（零 API Key）。

### 安装

```bash
# 方式1：通过 npx skills 安装（推荐，自动注册为 Skill）
npx skills add machina-sports/sports-skills@football-data

# 方式2：通过 pip 安装（需要 Python 3.10+）
pip install sports-skills

# 如果 pip 找不到包，从 GitHub 安装：
pip install git+https://github.com/machina-sports/sports-skills.git
```

> **注意**：需要 Python 3.10+。如果默认 Python 版本过低，使用 `python3.12 -m pip install sports-skills` 或创建新 conda 环境：`conda create -n worldcup python=3.12 && conda activate worldcup`

### 常用命令（CLI）

```bash
sports-skills football get_daily_schedule                              # 今日所有比赛
sports-skills football get_current_season --competition_id=world-cup   # 获取当前赛季ID
sports-skills football get_season_standings --season_id=<season_id>    # 积分榜
sports-skills football get_event_summary --event_id=<id>               # 比赛详情
sports-skills football get_event_timeline --event_id=<id>              # 进球/红牌/换人时间线
sports-skills football get_event_statistics --event_id=<id>            # 控球率/射门等
sports-skills football get_event_lineups --event_id=<id>               # 首发阵容
sports-skills football search_team --query="Argentina"                 # 搜索球队
sports-skills football search_player --query="Messi"                   # 搜索球员
sports-skills football get_team_schedule --team_id=<id>                # 球队赛程
sports-skills football get_season_teams --season_id=<season_id>        # 赛季所有球队
sports-skills football get_player_profile --fpl_id=<id>                # 球员资料
sports-skills football get_season_transfers --season_id=<season_id>    # 转会记录
```

### Python SDK（替代 CLI）

```python
from sports_skills import football

standings = football.get_season_standings(season_id="world-cup-2026")
schedule = football.get_daily_schedule()
```

### 关键规则

1. **调用前必须先获取 season_id**：用 `get_current_season(competition_id="world-cup")` 获取，不要硬编码
2. **team_id 必须通过查询获取**：用 `search_team(query="球队名")` 获取，不要猜测
3. **get_head_to_head 不可用**：该命令已废弃，始终返回空结果
4. **get_event_xg 仅限五大联赛**：世界杯不支持 xG 数据
5. **get_season_leaders 仅限英超**：世界杯不支持

## 功能模块与触发

### 赛前：帮人「看懂」

| 功能 | 触发关键词 | 实现方式 |
|------|-----------|---------|
| 足球规则速成 | 规则、越位、VAR、红黄牌、点球、角球、任意球 | 读取 `references/football_rules.md` |
| 2026新赛制解读 | 赛制、48队、出线规则、小组赛、淘汰赛 | 读取 `references/worldcup_2026_format.md` |
| 48强球队速览 | 某队实力、分组、谁强谁弱 | 读取 `references/team_profiles.md` |
| 球星档案 | 某球员、球星故事、梅西、C罗、姆巴佩 | 读取 `references/player_profiles.md` + football-data 查询 |
| 世界杯有趣知识 | 冷知识、趣事、历史、故事 | 读取 `references/worldcup_fun_facts.md` |

### 赛中：帮人「看爽」

| 功能 | 触发关键词 | 实现方式 |
|------|-----------|---------|
| 当日赛程播报 | 今天比赛、赛程、几点、今晚 | `get_daily_schedule` + 球队资料生成播报 |
| 小组赛出线形势 | 出线、积分、谁晋级、算分 | `get_season_standings` + 计算分析 |

### 赛后：帮人「聊得上」

| 功能 | 触发关键词 | 实现方式 |
|------|-----------|---------|
| 赛后社交文案 | 文案、朋友圈、公众号、小红书、发帖 | `get_event_summary` + `get_event_timeline` + `references/social_media_templates.md` |
| 比赛亮点回顾 | 回顾、高光、进球、红牌、绝杀 | `get_event_timeline` + `get_event_statistics` |

### 全程：帮人「玩起来」

| 功能 | 触发关键词 | 实现方式 |
|------|-----------|---------|
| 主队应援指南 | 球迷、助威、文化、歌曲 | 读取 `references/fan_culture.md` |
| 世界杯有趣知识 | 冷知识、聊天素材、你知道吗 | 读取 `references/worldcup_fun_facts.md` |

## 核心工作流

### 赛程播报

1. `get_daily_schedule` 获取今日比赛
2. 对每场：`search_team` 获取双方 team_id 和基本信息
3. 读取 `references/team_profiles.md` 补充中文介绍和历史战绩
4. 输出：对阵 + 北京时间 + 关键看点 + 预测

> 注：`get_head_to_head` 已废弃不可用，历史交锋信息从 team_profiles.md 中获取。

### 赛后文案

1. `get_event_summary` 获取比分
2. `get_event_timeline` 获取进球/红牌/换人
3. `get_event_statistics` 获取控球/射门数据
4. 读取 `references/social_media_templates.md` 获取模板
5. 生成三种风格：
   - **朋友圈**：50字内，有梗有情绪
   - **公众号**：500-800字，数据+战术分析
   - **小红书**：标题党+干货+互动引导

### 出线形势分析

1. `get_season_standings` 获取小组积分
2. 计算剩余比赛的所有可能结果
3. 列出各队出线条件
4. 用通俗语言解释

## 输出规范

- 中文为主，球队名/球员名保留英文并附中文（如 Argentina 阿根廷）
- 时间统一北京时间（UTC+8）
- 善用 emoji 增强可读性
- 实时数据必须来自 football-data，不编造

## 参考文件

| 文件 | 内容 | 何时读取 |
|------|------|---------|
| `references/football_rules.md` | 足球规则速成 | 用户问规则 |
| `references/worldcup_2026_format.md` | 2026新赛制 | 用户问赛制/出线 |
| `references/team_profiles.md` | 48强球队介绍 | 用户问球队 |
| `references/player_profiles.md` | 球星档案 | 用户问球员 |
| `references/worldcup_fun_facts.md` | 世界杯有趣知识 | 用户要冷知识 |
| `references/fan_culture.md` | 球迷文化指南 | 用户问助威/文化 |
| `references/social_media_templates.md` | 社媒文案模板 | 用户要文案 |
