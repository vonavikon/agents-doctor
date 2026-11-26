# Glossary: checks and findings in plain words

Generated from `scripts/glossary.py` by `tools/gen_glossary.py`; do not edit by hand.

Reports and summaries carry codes: `G5` for a check (gate), `SKL_FRONTMATTER_INVALID` for a kind of finding. Codes are for tools. People read the names below. In an answer to the user, name a check or a finding by its name and never by its code; the code is needed only for the `explain` and `fix` modes. When the user writes in Russian, answer with the Russian names.

## Checks (gates)

| Code | Name (ru) | Name (en) | What it checks |
| --- | --- | --- | --- |
| `G1` | Структура папок | Folder structure | папки разложены разумно, проекты не вложены друг в друга / folders are laid out sensibly, projects are not nested inside one another |
| `G2` | Файлы настроек | Settings files | файлы настроек агента читаются и не содержат ошибок / the agent's settings files open and hold no errors |
| `G3` | Инструкции агента | Agent instructions | инструкции не противоречат друг другу, ссылки в них живые, объём по силам агенту / instructions agree with each other, their links work, and they fit what the agent can read |
| `G4` | Папки без истории изменений | Folders without version history | у важных папок есть история изменений или резервная копия / important folders have version history or a backup |
| `G5` | Навыки агента | Agent skills | навыки оформлены правильно, и агент может их загрузить / skills are written correctly and the agent can load them |
| `G6` | Пароли и ключи | Passwords and keys | в файлах и в истории проекта не осталось ключей и паролей / no passwords or keys are left in files or in project history |
| `G7` | Сохранение работы | Saved work | работа сохранена в Git, лишнее не попадает в историю / work is saved in Git and stray files stay out of history |
| `G8` | Правила и подключения | Rules and connections | нет правил для неиспользуемых инструментов и дублей в подключениях / no rules kept for unused tools and no duplicate connections |
| `G9` | Мусор и лишние файлы | Junk and extra files | мусора и лишних копий немного / junk and extra copies are within reason |

## Status of a check

| Status | ru | en |
| --- | --- | --- |
| `fail` | красная | red |
| `warn` | жёлтая | yellow |
| `pass` | зелёная | green |
| `unknown` | не проверено | not checked |
| `not_applicable` | неприменимо | not applicable |

## Severity and status of a finding

| Severity | ru | en | | Finding status | ru | en |
| --- | --- | --- | --- | --- | --- | --- |
| `critical` | критично | critical | | `fail` | нужно исправить | to fix |
| `high` | важно | high | | `warn` | стоит посмотреть | worth a look |
| `medium` | заметно | medium | | `unknown` | не проверено | not checked |
| `low` | мелочь | low | | `pass` | в порядке | fine |
| `info` | справочно | info | | `not_applicable` | неприменимо | not applicable |

## Виды находок (ru)

| Code | Название | Что сделать |
| --- | --- | --- |
| `CFG_DUPLICATE_KEY` | В файле настроек одна настройка записана дважды | Удалите повторяющуюся строку, оставив нужное значение. |
| `CFG_FILE_UNPARSEABLE` | Файл настроек повреждён | Исправьте ошибку в указанном файле настроек. |
| `CFG_NO_CONFIG_FILES` | Файлы настроек не найдены | Если вы работаете с агентом в этой папке, проверьте, где лежат его настройки. |
| `CLAUDE_AGENTS_FRONTMATTER` | У вспомогательного агента Claude Code не заполнена шапка файла | Добавьте в шапку каждого файла агента в .claude/agents строки name (имя) и description (описание). |
| `CLAUDE_HOOKS_INVALID` | Автоматические команды Claude Code настроены с ошибкой | Откройте файл настроек и исправьте команду: у неё неизвестное событие или нет самой команды. |
| `CLAUDE_IMPORT_DEPTH` | Цепочка подключений через @ в Claude Code слишком длинная | Сократите цепочку подключений через @ до пяти шагов: файлы глубже Claude Code не загружает. |
| `CLAUDE_IMPORT_MISSING` | Claude Code подключает через @ несуществующий файл | Исправьте путь к файлу в строке с @ в файле инструкции или уберите эту строку. |
| `CLAUDE_IMPORT_OUTSIDE` | Claude Code подключает файл вне рабочей и домашней папки | Проверьте этот файл отдельно: он лежит вне папки аудита и домашней папки, поэтому аудит его не читал. |
| `CLAUDE_LOCAL_DEPRECATED` | Claude Code считает локальный файл инструкции устаревшим | Перенесите текст из файла CLAUDE.local.md в CLAUDE.md или в отдельное правило внутри .claude/rules и удалите старый файл. |
| `CLAUDE_MCP_DUPLICATE_SERVERS` | Один MCP-сервер описан в двух файлах Claude Code | Оставьте MCP-сервер только в одном файле, для проекта лучше в .mcp.json. |
| `CLAUDE_RULES_GLOB_NOMATCH` | Правило Claude Code не действует ни на один файл | Исправьте маску файлов (globs) в шапке правила из .claude/rules так, чтобы она находила реальные файлы, или удалите правило. |
| `CLAUDE_SETTINGS_DANGEROUS` | В настройках Claude Code агент работает без запросов разрешения | Уберите из файла настроек параметр dangerouslySkipPermissions или bypassPermissionsMode и перечислите вместо него только нужные разрешения. |
| `CLAUDE_SETTINGS_PERMISSIONS_WILDCARD` | Настройки Claude Code разрешают агенту слишком многое | Замените в файле настроек разрешения со звёздочкой (*) на разрешения только для нужных инструментов и адресов. |
| `CODEX_APPROVAL_NEVER` | Codex действует без запросов разрешения | Замените в файле .codex/config.toml approval_policy = never на on-request, чтобы Codex спрашивал разрешение перед рискованными шагами. |
| `CODEX_CHAIN_BUDGET` | Файлы инструкций Codex в сумме слишком большие | Сократите файлы инструкций AGENTS.md: уберите лишний текст или перенесите правила отдельных папок в AGENTS.md внутри этих папок. |
| `CODEX_MCP_ENV_SECRETS` | В настройках Codex ключи MCP-серверов лежат открытым текстом | Перенесите ключи MCP-серверов из файла .codex/config.toml в переменные окружения, оставьте в файле ссылки на них и замените эти ключи новыми. |
| `CODEX_OVERRIDE_IGNORED` | Codex работает от файла-замены вместо основной инструкции | Добавьте в корень проекта файл AGENTS.md с основными правилами или удалите файл AGENTS.override.md (он заменяет основную инструкцию). |
| `CODEX_SANDBOX_DANGER` | Codex работает без песочницы (ограничения прав агента) | Поставьте в файле .codex/config.toml sandbox_mode = workspace-write или строже и оставьте запрос разрешения для действий вне рабочей папки. |
| `CODEX_TOML_PARSE` | Файл настроек Codex повреждён или не проверен | Проверьте, что файл .codex/config.toml записан без синтаксических ошибок, и запустите аудит заново: для этой проверки нужен Python 3.11 или новее. |
| `COPILOT_AGENT_FILES` | У файла агента GitHub Copilot нет описания в шапке | Добавьте в шапку каждого файла агента в .github/agents строку description с описанием. |
| `COPILOT_APPLYTO_NOMATCH` | Инструкция GitHub Copilot не действует ни на один файл | Исправьте маску файлов в строке applyTo так, чтобы она находила существующие файлы, или удалите файл инструкции. |
| `COPILOT_INSTRUCTIONS_MISSING_APPLYTO` | Инструкция GitHub Copilot не привязана ни к каким файлам | Добавьте в шапку файла инструкции в .github/instructions строку applyTo с маской файлов или перенесите текст в .github/copilot-instructions.md. |
| `COPILOT_MAIN_TOO_BIG` | Главный файл инструкции GitHub Copilot слишком большой | Сократите .github/copilot-instructions.md до 25 КБ и перенесите правила для отдельных файлов в .github/instructions со строкой applyTo. |
| `COPILOT_MCP_JSON_PARSE` | Файл MCP-серверов GitHub Copilot повреждён | Исправьте синтаксис JSON в .github/mcp.json. |
| `COPILOT_MCP_YAML_HEURISTIC` | Файл MCP-серверов GitHub Copilot выглядит повреждённым | Проверьте синтаксис YAML в .github/copilot-mcp.yml: в файле должны быть записи вида servers: на верхнем уровне. |
| `COPILOT_PROMPT_FRONTMATTER` | У файла запроса GitHub Copilot нет описания в шапке | Добавьте в шапку каждого файла запроса в .github/prompts строку description с описанием. |
| `CURSOR_GLOB_INVALID` | В правиле Cursor маска файлов написана с ошибкой | Исправьте маску файлов (globs) в шапке правила: двойная звёздочка должна занимать целый элемент пути, как в src/**, а пустые записи уберите. |
| `CURSOR_GLOB_NOMATCH` | Правило Cursor не действует ни на один файл | Исправьте маску файлов (globs) в шапке правила так, чтобы она находила существующие файлы, или удалите правило. |
| `CURSOR_LEGACY_AND_RULES` | У Cursor есть и старые, и новые правила | Перенесите текст из старого файла .cursorrules в файлы правил в .cursor/rules и удалите старый файл. |
| `CURSOR_MCP_PARSE` | Файл MCP-серверов Cursor заполнен с ошибкой | Исправьте синтаксис JSON в .cursor/mcp.json и укажите серверы в блоке mcpServers, а если серверы не нужны, удалите файл. |
| `CURSOR_MDC_FRONTMATTER` | У правила Cursor нет описания в шапке файла | Добавьте в шапку каждого файла правила в .cursor/rules строку description с описанием. |
| `CURSOR_RULES_DUPLICATE_DESC` | У нескольких правил Cursor одинаковое описание | Дайте каждому правилу в .cursor/rules своё описание, из которого видно, зачем оно нужно. |
| `CURSOR_RULE_NO_SCOPE` | Правило Cursor включается только вручную | Добавьте в шапку правила в .cursor/rules хотя бы описание (description): иначе Cursor применяет правило только вручную. |
| `DIR_HEAVY_OUTSIDE_GIT` | Большая папка без резервной копии | Решите, что это за папка: сохраните в Git, заархивируйте или удалите. |
| `DIR_INSTRUCTION_PAIR_DRIFT` | Два файла инструкций разошлись | Оставьте один файл источником правил, а во втором оставьте ссылку на первый. |
| `DIR_LOOSE_TOP_FOLDERS` | Папки лежат вне истории изменений | Решите для каждой папки: держать в Git, заархивировать или удалить. |
| `DIR_MULTI_HARNESS_PROJECT_DIRS` | Настройки заведены сразу для нескольких инструментов | Оставьте настройки только тех инструментов, которыми действительно пользуетесь. |
| `DIR_NESTED_REPOSITORY` | Проект лежит внутри другого проекта | Вынесите внутренний проект в отдельную папку. |
| `FACTS_SECTION_MISSING` | Проверка не выполнена | Запустите аудит заново: нужные сведения не собрались. |
| `GEMINI_COMMANDS_FRONTMATTER` | Команда Gemini CLI записана с ошибкой или без описания | Проверьте файлы команд в .gemini/commands: исправьте в них ошибки TOML и добавьте в каждую команду строку description. |
| `GEMINI_EXTENSION_LAYOUT` | В папке расширения Gemini CLI нет файла инструкции | Добавьте в эту папку внутри .gemini/extensions файл GEMINI.md или удалите папку. |
| `GEMINI_IMPORT_DEPTH` | Цепочка подключений через @ в Gemini CLI слишком длинная | Сократите цепочку подключений через @ до пяти шагов: файлы глубже Gemini CLI не загружает. |
| `GEMINI_IMPORT_MISSING` | Gemini CLI подключает через @ несуществующий файл | Исправьте путь после @ в файле инструкции или создайте файл по этому пути: относительный путь отсчитывается от папки, где лежит сам файл инструкции. |
| `GEMINI_NESTED_ORPHAN` | У Gemini CLI нет общей инструкции в корне проекта | Перенесите общие правила в файл GEMINI.md в корне проекта или оставьте как есть, если правила нужны только во вложенных папках. |
| `GEMINI_SETTINGS_PARSE` | Файл настроек Gemini CLI заполнен с ошибкой | Исправьте файл .gemini/settings.json: он должен быть одним JSON-объектом, а excludeTools и coreTools в нём должны быть списками. |
| `GIT_MULTIPLE_CHECKOUTS` | Проект скачан несколько раз | Оставьте одну копию проекта. |
| `GIT_NO_GITIGNORE` | В проекте нет файла .gitignore | Добавьте .gitignore, чтобы мусор и личные настройки не попадали в историю. |
| `GIT_TRACKED_FILE_TOO_BIG` | В историю попал слишком большой файл | Уберите файл из истории проекта. |
| `GIT_UNCOMMITTED_WORK` | Есть несохранённая работа | Сохраните изменения или отложите их, чтобы не потерять. |
| `GOV_DEAD_HARNESS_INSTRUCTIONS` | Правила ведутся для инструмента, которым давно не пользуются | Удалите эти инструкции или сократите до ссылки. |
| `GOV_MCP_DUPLICATE_KEY` | В подключениях один сервер записан дважды | Удалите повторяющийся блок. |
| `HLTH_EMPTY_DIRS` | Много пустых папок | Удалите пустые папки. |
| `HLTH_HARNESS_OCCASIONAL` | Инструментом давно не пользовались | Решите: оставить инструмент с его настройками или убрать. |
| `HLTH_JUNK_OVER_LIMIT` | Мусора стало слишком много | Удалите папки сборки и старые копии. |
| `HLTH_LARGE_FILE_OUTSIDE_GIT` | Большой файл без резервной копии | Сохраните файл в историю или удалите. |
| `HLTH_UNUSED_DATA` | Похоже на неиспользуемый файл или папку | Посмотрите и удалите либо уберите в архив. |
| `INSTR_CONTRADICTION` | Инструкции агента противоречат друг другу | Решите, какое правило правильное, и уберите второе. |
| `INSTR_DIVERGENCE` | Инструкции разных агентов расходятся в одном вопросе | Убедитесь, что расхождение намеренное: если нет, приведите оба файла инструкции к одному правилу. |
| `INSTR_DUPLICATION` | Одинаковый текст повторяется в двух файлах инструкции | Оставьте повторяющийся кусок только в одном файле инструкции и удалите его из остальных. |
| `OPENCODE_AGENT_FRONTMATTER` | У файла агента OpenCode нет описания в шапке | Добавьте в шапку файла агента в .opencode/agent строку description с кратким описанием. |
| `OPENCODE_CONFIG_PARSE` | OpenCode не может прочитать файл настроек | Исправьте синтаксис JSON в файле opencode.json или opencode.jsonc, а в jsonc пишите комментарии отдельными строками, начиная строку с //. |
| `OPENCODE_GLOBAL_LOCAL_DRIFT` | Общая и проектная инструкции OpenCode повторяют друг друга | Оставьте повторяющиеся строки только в одном месте: правила проекта в AGENTS.md в корне проекта, общие привычки в .config/opencode/AGENTS.md в домашней папке. |
| `OPENCODE_INSTRUCTION_MISSING` | OpenCode не находит файл инструкции из настроек | Создайте файл инструкции, указанный в файле настроек, или исправьте путь в параметре instruction. |
| `OPENCODE_MCP_PARSE` | Блок MCP-серверов в настройках OpenCode заполнен неверно | Запишите в файле настроек блок mcp как набор серверов, где у каждого есть имя и параметры, например command. |
| `OPENCODE_PERMISSIONS_DANGEROUS` | Настройки OpenCode дают агенту слишком много прав | Сузьте права в файле настроек: перечислите разрешённые команды и пути, добавьте запреты для остальных и поставьте ask (запрос разрешения) на всё остальное. |
| `RUL_CHAIN_OVER_BUDGET` | Инструкции стали слишком длинными для агента | Сократите общий объём инструкций: иначе агент может не увидеть их целиком. |
| `RUL_CONTRADICTIONS` | Инструкции противоречат друг другу | Решите, какое правило верное, и уберите второе. |
| `RUL_DEAD_REFERENCE` | В инструкциях есть ссылка на то, чего нет | Исправьте ссылку или верните файл на место. |
| `RUL_FILE_TOO_BIG` | Файл инструкций слишком большой | Сократите файл: агенту хватает коротких конкретных правил. |
| `RUL_GENERIC_BOILERPLATE` | В инструкциях есть шаблонный текст | Замените общие фразы правилами для вашего проекта. |
| `RUL_GENERIC_PHRASES` | В инструкциях много общих советов | Уберите советы, которые подходят любому проекту. |
| `RUL_MOSTLY_NOISE` | В файле инструкций много текста без конкретных правил | Сократите файл: оставьте конкретные правила, уберите пояснения и повторы. |
| `RUL_REDUNDANT_RULES` | В инструкциях есть повторяющиеся правила | Уберите повторы. |
| `RUL_SHORT_FILE_HINT` | Короткий файл инструкций: правил в нём почти нет | Если это ссылка на другой файл с правилами, всё в порядке. Если правила должны быть здесь, добавьте их. |
| `RUL_TWO_RULE_SOURCES` | Правила ведутся в двух файлах сразу | Оставьте один источник правил, второй сделайте ссылкой на него. |
| `SEC_CREDENTIALS_IN_REMOTE` | В адресе проекта записан пароль | Перенесите пароль в хранилище паролей системы и смените его. |
| `SEC_EXPOSED_SECRET` | В файле лежит пароль или ключ | Сначала смените ключ у того, кто его выдал, затем уберите его из файла. |
| `SEC_GIT_SIDE_UNVERIFIED` | Некоторые папки с Git не проверены на ключи | Проверьте каждую из этих папок отдельным аудитом. |
| `SEC_HISTORY_SCAN_INCOMPLETE` | История проекта проверена не полностью | Запустите аудит с полной проверкой истории. |
| `SEC_PREVENTION_ABSENT` | Нет защиты от попадания ключей в историю проекта | Поставьте автоматическую проверку ключей перед сохранением. |
| `SEC_PREVENTION_UNVERIFIED` | В непроверенных папках с Git не смотрели защиту от ключей | Проверьте каждую из этих папок отдельным аудитом. |
| `SEC_SECRET_IN_HISTORY` | Ключ остался в старой истории проекта | Сначала смените ключ, затем вычистите его из истории. |
| `SEC_TRACKED_SECRET` | Ключ попал в сохранённую историю проекта | Сначала смените ключ, затем уберите файл из истории и перепишите её. |
| `SEC_TRACKED_SECRET_BUNDLE` | Возможно, ключ в большом файле проекта (библиотека или сборка) | Посмотрите указанную строку вручную: в таких файлах обычно примеры, а не настоящие ключи. Смените ключ, только если он настоящий. |
| `SKL_CHECK_INCOMPLETE` | Навыки проверены не все | Проверьте оставшиеся навыки, сузив папку аудита. |
| `SKL_COPIES_DIVERGED` | Копии одного навыка разошлись | Оставьте одну копию, остальные удалите или синхронизируйте. |
| `SKL_DEAD_REFERENCE` | Навык ссылается на отсутствующий файл | Верните файл на место или уберите ссылку. |
| `SKL_DESCRIPTION_TOO_LONG` | Описание навыка слишком длинное | Сократите описание, подробности перенесите в текст навыка. |
| `SKL_FOLDER_UNREADABLE` | Папку навыков не удалось прочитать | Разберитесь с доступом к папке и запустите аудит заново. |
| `SKL_FRONTMATTER_INVALID` | Шапка файла навыка содержит ошибку | Исправьте шапку в указанной строке (чаще всего нужно взять значение в кавычки). |
| `SKL_FRONTMATTER_UNKNOWN` | Шапка файла навыка не проверена | Проверьте шапку файла вручную. |
| `SKL_NO_TRIGGERS` | У навыка не написано, когда его применять | Добавьте в описание фразу вида «используйте, когда…». |
| `SKL_REQUIRED_FIELD_MISSING` | В шапке файла навыка нет обязательного поля | Добавьте недостающее поле в шапку файла. |
| `WINDSURF_GLOB_MISSING` | Правило Windsurf должно включаться по маске, но маски нет | Добавьте в шапку правила строку glob с маской файлов или смените trigger на always или manual. |
| `WINDSURF_GLOB_NOMATCH` | Правило Windsurf не действует ни на один файл | Исправьте маску файлов в строке glob так, чтобы она находила существующие файлы, или удалите правило. |
| `WINDSURF_LEGACY_AND_RULES` | У Windsurf есть и старые, и новые правила | Перенесите текст из старого файла .windsurfrules в файлы правил в .windsurf/rules и удалите старый файл. |
| `WINDSURF_MCP_PARSE` | Файл MCP-серверов Windsurf повреждён | Исправьте синтаксис JSON в .windsurf/mcp_config.json. |
| `WINDSURF_RULE_NO_TRIGGER` | У правила Windsurf не указано, когда оно включается | Добавьте в шапку каждого правила в .windsurf/rules строку trigger со значением always, glob, manual или model_decision. |
| `WINDSURF_TRIGGER_UNKNOWN` | В правиле Windsurf указано неизвестное условие включения | Поставьте в строке trigger правила одно из значений: always, glob, manual или model_decision. |
| `ZCODE_MEMORY_OVER_LIMIT` | Файл памяти Z Code слишком большой | Сократите файл памяти Z Code (в домашней папке: .zcode/cli/memories/MEMORY.md): подробности перенесите в отдельные файлы по темам, а в нём оставьте по одной строке на тему. |

`SEC_EXPOSED_SECRET` has three faces, by the `git` value of its evidence:

| `git` | Название | Что сделать |
| --- | --- | --- |
| `ignored` | В файле настроек лежит ключ (в Git он не попадает) | Это обычное место для личных настроек. Смените ключ, только если файл уходил с компьютера: его пересылали, выкладывали или синхронизировали через облако. |
| `tracked` | В файле, который хранится в Git, лежит пароль или ключ | Файл с ключом уходит каждому, у кого есть копия проекта. Сначала смените ключ у того, кто его выдал, затем уберите файл из проекта и из его истории. |
| `untracked` | В файле лежит пароль или ключ | Файл ещё не в Git, но лежит в папке проекта и может попасть в историю при следующем сохранении. Добавьте его в .gitignore. Если файл куда-то отправляли, смените ключ. |

## Kinds of findings (en)

| Code | Name | What to do |
| --- | --- | --- |
| `CFG_DUPLICATE_KEY` | One setting is written twice in a settings file | Remove the repeated line and keep the value you need. |
| `CFG_FILE_UNPARSEABLE` | A settings file is damaged | Fix the error in the settings file named. |
| `CFG_NO_CONFIG_FILES` | No settings files found | If you use an agent in this folder, check where its settings live. |
| `CLAUDE_AGENTS_FRONTMATTER` | Claude Code subagent file has an incomplete header | Add name and description lines to the header of each agent file in .claude/agents. |
| `CLAUDE_HOOKS_INVALID` | Claude Code automatic commands are set up incorrectly | Open the settings file and fix the command: its event is unknown or the command itself is missing. |
| `CLAUDE_IMPORT_DEPTH` | Claude Code chain of @ imports is too long | Shorten the chain of @ imports to five steps: Claude Code does not load deeper files. |
| `CLAUDE_IMPORT_MISSING` | Claude Code imports a file that does not exist | Fix the file path on the @ line in the instruction file or remove that line. |
| `CLAUDE_IMPORT_OUTSIDE` | Claude Code imports a file outside the workspace and home | Check the imported file yourself: it lies outside the workspace folder and your home folder, so the scan did not read it. |
| `CLAUDE_LOCAL_DEPRECATED` | Claude Code treats the local instruction file as outdated | Move the text from CLAUDE.local.md into CLAUDE.md or into a separate rule inside .claude/rules and delete the old file. |
| `CLAUDE_MCP_DUPLICATE_SERVERS` | Claude Code lists the same MCP server twice | Keep the MCP server in one file only, preferably .mcp.json for a project server. |
| `CLAUDE_RULES_GLOB_NOMATCH` | A Claude Code rule applies to no file | Fix the file mask (globs) in the header of the rule from .claude/rules so that it finds real files, or delete the rule. |
| `CLAUDE_SETTINGS_DANGEROUS` | Claude Code settings let the agent work without permission prompts | Remove the dangerouslySkipPermissions or bypassPermissionsMode flag from the settings file and list only the permissions the agent needs. |
| `CLAUDE_SETTINGS_PERMISSIONS_WILDCARD` | Claude Code settings allow the agent too much | In the settings file, replace the asterisk (*) permissions with narrow ones for only the tools and hosts you need. |
| `CODEX_APPROVAL_NEVER` | Codex acts without asking for permission | Change approval_policy = never to on-request in .codex/config.toml so that Codex asks before risky steps. |
| `CODEX_CHAIN_BUDGET` | Codex instruction files are too large together | Shorten the AGENTS.md instruction files: remove extra text or move the rules of separate folders into the AGENTS.md inside those folders. |
| `CODEX_MCP_ENV_SECRETS` | Codex settings contain MCP server keys in plain text | Move the MCP server keys from .codex/config.toml into environment variables, leave references to them in the file, and replace the exposed keys with new ones. |
| `CODEX_OVERRIDE_IGNORED` | Codex runs from an override file with no base instructions | Add an AGENTS.md file to the project root or delete AGENTS.override.md. |
| `CODEX_SANDBOX_DANGER` | Codex runs without its sandbox (permission limits) | Set sandbox_mode = workspace-write or stricter in .codex/config.toml and keep a permission prompt for actions outside the workspace. |
| `CODEX_TOML_PARSE` | Codex settings file is broken or was not checked | Check that the .codex/config.toml file has no syntax errors and run the audit again: this check needs Python 3.11 or newer. |
| `COPILOT_AGENT_FILES` | GitHub Copilot agent file has no description in its header | Add a description line to the header of each agent file in .github/agents. |
| `COPILOT_APPLYTO_NOMATCH` | GitHub Copilot instruction applies to no file | Fix the file mask in the applyTo line so that it finds existing files, or delete the instruction file. |
| `COPILOT_INSTRUCTIONS_MISSING_APPLYTO` | GitHub Copilot instruction file is tied to no files | Add an applyTo line with a file mask to the header of the instruction file in .github/instructions, or move the text into .github/copilot-instructions.md. |
| `COPILOT_MAIN_TOO_BIG` | Main GitHub Copilot instruction file is too large | Cut .github/copilot-instructions.md down to 25 KB and move the rules for separate files into .github/instructions with an applyTo line. |
| `COPILOT_MCP_JSON_PARSE` | GitHub Copilot MCP server file is not valid JSON | Fix the JSON syntax in .github/mcp.json. |
| `COPILOT_MCP_YAML_HEURISTIC` | GitHub Copilot MCP server file looks broken | Check the YAML syntax in .github/copilot-mcp.yml: the file needs top-level entries like servers:. |
| `COPILOT_PROMPT_FRONTMATTER` | GitHub Copilot prompt file has no description in its header | Add a description line to the header of each prompt file in .github/prompts. |
| `CURSOR_GLOB_INVALID` | A Cursor rule has a malformed file mask | Fix the file mask (globs) in the rule header: a double asterisk must take a whole path part, as in src/**, and remove empty entries. |
| `CURSOR_GLOB_NOMATCH` | A Cursor rule applies to no file | Fix the file mask (globs) in the rule header so that it finds existing files, or delete the rule. |
| `CURSOR_LEGACY_AND_RULES` | Cursor has both old and new rule files | Move the text from the old .cursorrules file into rule files in .cursor/rules and delete the old file. |
| `CURSOR_MCP_PARSE` | Cursor MCP server file has an error | Fix the JSON syntax in .cursor/mcp.json and list the servers under the mcpServers key, or delete the file if you need no servers. |
| `CURSOR_MDC_FRONTMATTER` | A Cursor rule has no description in its header | Add a description line to the header of each rule file in .cursor/rules. |
| `CURSOR_RULES_DUPLICATE_DESC` | Several Cursor rules have the same description | Give each rule in .cursor/rules its own description that says what the rule is for. |
| `CURSOR_RULE_NO_SCOPE` | A Cursor rule turns on only by hand | Add alwaysApply, globs or at least a description to the header of the rule file in .cursor/rules so that Cursor applies the rule without manual steps. |
| `DIR_HEAVY_OUTSIDE_GIT` | A large folder has no backup | Decide what the folder is: put it in Git, archive it or delete it. |
| `DIR_INSTRUCTION_PAIR_DRIFT` | Two instruction files have grown apart | Keep one file as the source of rules and turn the other into a pointer to it. |
| `DIR_LOOSE_TOP_FOLDERS` | Folders sit outside version history | For each folder decide: keep in Git, archive or delete. |
| `DIR_MULTI_HARNESS_PROJECT_DIRS` | Settings exist for several tools at once | Keep settings only for the tools you really use. |
| `DIR_NESTED_REPOSITORY` | A project sits inside another project | Move the inner project out into a folder of its own. |
| `FACTS_SECTION_MISSING` | Check did not run | Run the audit again: the facts it needs were not collected. |
| `GEMINI_COMMANDS_FRONTMATTER` | Gemini CLI command is broken or lacks a description | Check the command files in .gemini/commands: fix TOML errors in them and add a description line to each command. |
| `GEMINI_EXTENSION_LAYOUT` | A Gemini CLI extension folder has no instruction file | Add a GEMINI.md file to that folder inside .gemini/extensions or delete the folder. |
| `GEMINI_IMPORT_DEPTH` | Gemini CLI chain of @ imports is too long | Shorten the chain of @ imports to five steps: Gemini CLI does not load deeper files. |
| `GEMINI_IMPORT_MISSING` | Gemini CLI imports a file that does not exist | Fix the path after @ in the instruction file or create the file at that path: a relative path starts from the folder of the instruction file itself. |
| `GEMINI_NESTED_ORPHAN` | Gemini CLI has no project-root instruction file | Move the shared rules into GEMINI.md at the project root, or leave things as they are if the rules are needed only in subfolders. |
| `GEMINI_SETTINGS_PARSE` | Gemini CLI settings file has an error | Fix the .gemini/settings.json file: it must be a single JSON object, and excludeTools and coreTools in it must be lists. |
| `GIT_MULTIPLE_CHECKOUTS` | The project is checked out several times | Keep one checkout of the project. |
| `GIT_NO_GITIGNORE` | The project has no .gitignore file | Add a .gitignore so junk and personal settings stay out of history. |
| `GIT_TRACKED_FILE_TOO_BIG` | A file that is too large got into history | Take the file out of the project history. |
| `GIT_UNCOMMITTED_WORK` | There is unsaved work | Save the changes or set them aside so they are not lost. |
| `GOV_DEAD_HARNESS_INSTRUCTIONS` | Rules are kept for a tool that is no longer used | Remove those instructions or cut them down to a pointer. |
| `GOV_MCP_DUPLICATE_KEY` | A connection server is listed twice | Remove the repeated block. |
| `HLTH_EMPTY_DIRS` | Many empty folders | Remove the empty folders. |
| `HLTH_HARNESS_OCCASIONAL` | A tool has not been used for a while | Decide whether to keep the tool and its settings or remove them. |
| `HLTH_JUNK_OVER_LIMIT` | There is too much junk | Delete build folders and old copies. |
| `HLTH_LARGE_FILE_OUTSIDE_GIT` | A large file has no backup | Put the file under version control or delete it. |
| `HLTH_UNUSED_DATA` | Looks like an unused file or folder | Have a look, then delete it or move it to an archive. |
| `INSTR_CONTRADICTION` | The agent instructions contradict each other | Decide which rule is right and remove the other one. |
| `INSTR_DIVERGENCE` | Instructions of different agent tools disagree | Make sure the difference is intended: if not, bring both instruction files to the same rule. |
| `INSTR_DUPLICATION` | The same text is repeated in two instruction files | Keep the repeated block in one instruction file only and remove it from the others. |
| `OPENCODE_AGENT_FRONTMATTER` | OpenCode agent file has no description in its header | Add a one-line description to the header of the agent file in .opencode/agent. |
| `OPENCODE_CONFIG_PARSE` | OpenCode cannot read its settings file | Fix the JSON syntax in opencode.json or opencode.jsonc, and in jsonc write comments on their own lines that start with //. |
| `OPENCODE_GLOBAL_LOCAL_DRIFT` | OpenCode global and project instructions repeat each other | Keep the repeated lines in one place only: project rules in AGENTS.md at the project root, machine-wide habits in .config/opencode/AGENTS.md in your home folder. |
| `OPENCODE_INSTRUCTION_MISSING` | OpenCode cannot find the instruction file named in its settings | Create the instruction file named in the settings file, or fix the path in the instruction setting. |
| `OPENCODE_MCP_PARSE` | MCP server section in OpenCode settings has the wrong shape | Write the mcp section in the settings file as a set of servers, each with a name and settings such as command. |
| `OPENCODE_PERMISSIONS_DANGEROUS` | OpenCode settings give the agent too many permissions | Narrow the permissions in the settings file: list the allowed commands and paths, deny the rest, and set ask (a permission prompt) for everything else. |
| `RUL_CHAIN_OVER_BUDGET` | The instructions grew too long for the agent | Cut the total size of the instructions, or the agent may not see all of them. |
| `RUL_CONTRADICTIONS` | The instructions contradict each other | Decide which rule is right and remove the other one. |
| `RUL_DEAD_REFERENCE` | The instructions point to something that does not exist | Fix the reference or put the file back. |
| `RUL_FILE_TOO_BIG` | An instruction file is too large | Shorten the file: the agent does well with short, specific rules. |
| `RUL_GENERIC_BOILERPLATE` | The instructions contain template text | Replace the generic phrases with rules for your project. |
| `RUL_GENERIC_PHRASES` | The instructions hold a lot of generic advice | Remove the advice that would fit any project. |
| `RUL_MOSTLY_NOISE` | An instruction file holds a lot of text with few concrete rules | Shorten the file: keep concrete rules, drop explanations and repeats. |
| `RUL_REDUNDANT_RULES` | The instructions repeat some rules | Remove the repeats. |
| `RUL_SHORT_FILE_HINT` | A short instruction file holds almost no rules | A pointer to another file with the rules is fine as it is. If the rules were meant to live here, add them. |
| `RUL_TWO_RULE_SOURCES` | Rules are kept in two files at once | Keep one source of rules and turn the other into a pointer to it. |
| `SEC_CREDENTIALS_IN_REMOTE` | The project address embeds a password | Move the password into the system credential store and change it. |
| `SEC_EXPOSED_SECRET` | A password or key is sitting in a file | First have the key reissued by whoever issued it, then remove it from the file. |
| `SEC_GIT_SIDE_UNVERIFIED` | Some git folders were not checked for keys | Check each of those folders with a separate audit. |
| `SEC_HISTORY_SCAN_INCOMPLETE` | The history of a project was not fully checked | Run the audit with a full history check. |
| `SEC_PREVENTION_ABSENT` | Nothing stops keys from getting into project history | Set up an automatic key check before each save. |
| `SEC_PREVENTION_UNVERIFIED` | The unchecked git folders were not looked at for key protection | Check each of those folders with a separate audit. |
| `SEC_SECRET_IN_HISTORY` | A key is left in the old history of a project | Have the key reissued first, then scrub it out of the history. |
| `SEC_TRACKED_SECRET` | A key got into the saved history of a project | Have the key reissued first, then drop the file from history and rewrite it. |
| `SEC_TRACKED_SECRET_BUNDLE` | A key may sit in a large project file (a library or a bundle) | Look at the line by hand: such files usually hold examples, not real keys. Have the key reissued only if it is a real one. |
| `SKL_CHECK_INCOMPLETE` | Not every skill was checked | Check the remaining skills by narrowing the audited folder. |
| `SKL_COPIES_DIVERGED` | Copies of one skill have grown apart | Keep one copy; delete or sync the rest. |
| `SKL_DEAD_REFERENCE` | A skill points to a file that does not exist | Put the file back or drop the reference. |
| `SKL_DESCRIPTION_TOO_LONG` | A skill description is too long | Shorten the description and move the details into the skill body. |
| `SKL_FOLDER_UNREADABLE` | A skills folder could not be read | Fix access to the folder and run the audit again. |
| `SKL_FRONTMATTER_INVALID` | The header of a skill file has an error | Fix the header on the line named (most often the value needs quotes). |
| `SKL_FRONTMATTER_UNKNOWN` | A skill header was not checked | Check the file header by hand. |
| `SKL_NO_TRIGGERS` | A skill does not say when to use it | Add a "use when ..." phrase to the description. |
| `SKL_REQUIRED_FIELD_MISSING` | A skill header lacks a required field | Add the missing field to the header of the file. |
| `WINDSURF_GLOB_MISSING` | Windsurf rule needs a file mask but has none | Add a glob line with a file mask to the rule header, or switch the trigger to always or manual. |
| `WINDSURF_GLOB_NOMATCH` | Windsurf rule applies to no file | Fix the file mask in the glob line so that it finds existing files, or delete the rule. |
| `WINDSURF_LEGACY_AND_RULES` | Windsurf has both old and new rule files | Move the text from the old .windsurfrules file into rule files in .windsurf/rules and delete the old file. |
| `WINDSURF_MCP_PARSE` | Windsurf MCP server file is not valid JSON | Fix the JSON syntax in .windsurf/mcp_config.json. |
| `WINDSURF_RULE_NO_TRIGGER` | Windsurf rule does not say when it turns on | Add a trigger line with the value always, glob, manual or model_decision to the header of each rule in .windsurf/rules. |
| `WINDSURF_TRIGGER_UNKNOWN` | Windsurf rule has an unknown trigger value | Set the trigger line of the rule to one of these values: always, glob, manual or model_decision. |
| `ZCODE_MEMORY_OVER_LIMIT` | The Z Code memory file is too large | Shorten the memory file .zcode/cli/memories/MEMORY.md in your home folder: move the details into separate topic files and keep one pointer line for each. |

`SEC_EXPOSED_SECRET` has three faces, by the `git` value of its evidence:

| `git` | Name | What to do |
| --- | --- | --- |
| `ignored` | A key sits in a settings file that Git keeps out | This is the usual place for personal settings. Have the key reissued only if the file left this computer: mailed, uploaded or synced through a cloud folder. |
| `tracked` | A password or key sits in a file kept in Git | Everyone who has a copy of the project gets the file. First have the key reissued by whoever issued it, then take the file out of the project and out of its history. |
| `untracked` | A password or key is sitting in a file | The file is not in Git yet, but it lies in the project folder and can get into history at the next save. Add it to .gitignore. Have the key reissued if the file was ever sent anywhere. |

## Why a check is "not checked" or "not applicable"

| Code | ru | en |
| --- | --- | --- |
| `facts_missing` | Сканер не собрал сведения, нужные для проверки | The facts this check needs were not collected |
| `frontmatter_unverified` | Ни одна шапка файла навыка не разобралась, проверять нечего | No skill header could be read, so there was nothing to check |
| `git_index_unverified` | Индекс Git этих репозиториев не читался | The git index of these repositories was not read |
| `git_nested_unverified` | Внутри папки есть репозитории, которые не проверены: их история и настройки не читались | Repositories inside the audited area were not checked: their history and settings were not read |
| `git_nested_unverified_one` | Внутри папки есть репозиторий, который не проверен: его история и настройки не читались | A repository inside the audited area was not checked: its history and settings were not read |
| `history_not_scanned` | История Git не проверялась на ключи | Git history was not scanned for keys |
| `history_partially_scanned` | История Git проверена на ключи не полностью | Git history was only partly scanned for keys |
| `no_git` | В папке нет ни одного Git-репозитория: советы про Git неприменимы (файлы на ключи всё равно проверены) | No git repositories in the audited area (files were still checked for keys) |
| `no_skill_folders` | В папке и в домашнем каталоге нет папок с навыками | No skill folders exist in the workspace or the home directory |
| `no_skills_found` | Навыки не найдены в N проверенных папках | No skills were found in the N checked folder(s) |
| `skills_copies_not_compared` | Копии навыков не сравнивались | The scan did not compare skill copies |
| `skills_facts_missing` | Сканер не собрал сведения о навыках | The scan produced no skills facts |
| `skills_folders_unreadable` | Папку навыков не удалось прочитать | A skills folder could not be read |
| `skills_search_incomplete` | Навыки проверены не все: поиск оборвался | Not every skill was checked: the search was cut short |
