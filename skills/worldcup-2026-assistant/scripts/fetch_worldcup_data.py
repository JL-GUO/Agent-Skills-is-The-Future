#!/usr/bin/env python3
"""
2026世界杯数据获取脚本
使用 football-data Skill (sports-skills) 获取实时数据并导出为 Markdown。

依赖：
    pip install sports-skills           # 需要 Python 3.10+
    # 或：pip install git+https://github.com/machina-sports/sports-skills.git

用法：
    python fetch_worldcup_data.py                    # 获取今日数据
    python fetch_worldcup_data.py --standings        # 获取积分榜
    python fetch_worldcup_data.py --event <id>       # 获取比赛详情
    python fetch_worldcup_data.py --search <team>    # 搜索球队
    python fetch_worldcup_data.py --all              # 获取所有数据
    python fetch_worldcup_data.py --check            # 检查依赖是否安装
"""

import subprocess
import sys
import shutil
from datetime import datetime


def check_dependency():
    """检查 sports-skills CLI 是否可用"""
    if shutil.which("sports-skills"):
        return True
    # 尝试 Python import
    try:
        result = subprocess.run(
            [sys.executable, "-c", "import sports_skills; print('OK')"],
            capture_output=True, text=True, timeout=10
        )
        return result.returncode == 0
    except Exception:
        return False


def run_command(cmd):
    """执行 CLI 命令并返回输出"""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=30,
            encoding="utf-8"
        )
        if result.returncode != 0:
            return f"命令执行失败: {result.stderr.strip()}"
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        return "命令超时（30秒）"
    except FileNotFoundError:
        return "错误: sports-skills 未安装。请运行: pip install sports-skills"
    except Exception as e:
        return f"执行错误: {e}"


def get_current_season():
    """获取世界杯当前赛季ID"""
    output = run_command(
        'sports-skills football get_current_season --competition_id="world-cup"'
    )
    return output


def get_today_matches():
    """获取今日赛程"""
    output = run_command("sports-skills football get_daily_schedule")
    return output


def get_standings(season_id=None):
    """获取世界杯积分榜"""
    if season_id is None:
        season_id = get_current_season()
        if "错误" in season_id or "失败" in season_id:
            return f"无法获取赛季ID: {season_id}"
    output = run_command(
        f'sports-skills football get_season_standings --season_id="{season_id}"'
    )
    return output


def get_event_summary(event_id):
    """获取比赛详情"""
    output = run_command(
        f'sports-skills football get_event_summary --event_id="{event_id}"'
    )
    return output


def get_event_timeline(event_id):
    """获取比赛时间线（进球/红牌/换人）"""
    output = run_command(
        f'sports-skills football get_event_timeline --event_id="{event_id}"'
    )
    return output


def get_event_statistics(event_id):
    """获取比赛统计数据（控球率/射门等）"""
    output = run_command(
        f'sports-skills football get_event_statistics --event_id="{event_id}"'
    )
    return output


def get_event_lineups(event_id):
    """获取比赛首发阵容"""
    output = run_command(
        f'sports-skills football get_event_lineups --event_id="{event_id}"'
    )
    return output


def search_team(query):
    """搜索球队"""
    output = run_command(
        f'sports-skills football search_team --query="{query}"'
    )
    return output


def search_player(query):
    """搜索球员"""
    output = run_command(
        f'sports-skills football search_player --query="{query}"'
    )
    return output


def get_team_schedule(team_id):
    """获取球队赛程"""
    output = run_command(
        f'sports-skills football get_team_schedule --team_id="{team_id}"'
    )
    return output


def export_markdown(data_type="daily", output_path=None):
    """导出数据为 Markdown 文件"""
    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    if output_path is None:
        output_path = f"worldcup_data_{datetime.now().strftime('%Y%m%d')}.md"

    content = f"# 世界杯数据更新 - {now}\n\n"

    if data_type in ("daily", "all"):
        content += "## 今日赛程\n\n"
        result = get_today_matches()
        content += f"```\n{result}\n```\n\n"

    if data_type in ("standings", "all"):
        content += "## 积分榜\n\n"
        result = get_standings()
        content += f"```\n{result}\n```\n\n"

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)

    print(f"数据已导出到: {output_path}")
    return content


def main():
    args = sys.argv[1:]

    # 检查依赖
    if "--check" in args:
        if check_dependency():
            print("sports-skills 已安装并可用")
            # 显示版本信息
            output = run_command("sports-skills --version 2>&1 || echo '版本未知'")
            print(f"版本: {output}")
        else:
            print("sports-skills 未安装")
            print("安装方式:")
            print("  pip install sports-skills                    # 需要 Python 3.10+")
            print("  pip install git+https://github.com/machina-sports/sports-skills.git")
            print("  npx skills add machina-sports/sports-skills@football-data  # 作为 Skill 安装")
        return

    # 检查依赖是否可用
    if not check_dependency():
        print("错误: sports-skills 未安装或不可用")
        print("请先安装: pip install sports-skills (需要 Python 3.10+)")
        print("或运行: python fetch_worldcup_data.py --check 查看安装指引")
        sys.exit(1)

    if "--standings" in args:
        export_markdown("standings")
    elif "--all" in args:
        export_markdown("all")
    elif "--matches" in args:
        print("今日赛程:")
        print(get_today_matches())
    elif "--event" in args:
        idx = args.index("--event")
        if idx + 1 < len(args):
            event_id = args[idx + 1]
            print(f"比赛详情 (event_id={event_id}):")
            print(get_event_summary(event_id))
            print("\n--- 时间线 ---")
            print(get_event_timeline(event_id))
            print("\n--- 统计数据 ---")
            print(get_event_statistics(event_id))
        else:
            print("请提供 event_id，如: python fetch_worldcup_data.py --event <id>")
    elif "--search" in args:
        idx = args.index("--search")
        if idx + 1 < len(args):
            query = args[idx + 1]
            print(f"搜索球队: {query}")
            print(search_team(query))
        else:
            print("请提供搜索关键词，如: python fetch_worldcup_data.py --search Brazil")
    elif "--player" in args:
        idx = args.index("--player")
        if idx + 1 < len(args):
            query = args[idx + 1]
            print(f"搜索球员: {query}")
            print(search_player(query))
        else:
            print("请提供球员名，如: python fetch_worldcup_data.py --player Messi")
    elif "--season" in args:
        print("当前世界杯赛季ID:")
        print(get_current_season())
    else:
        export_markdown("daily")


if __name__ == "__main__":
    main()
