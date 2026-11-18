# Atalhos para os testes — 18/11/2026

Windows: execute `.\testar.cmd` no PowerShell, dentro da pasta do projeto.
Raspberry/Linux: execute `sh testar.sh` na pasta do projeto.
Ambos chamam o mesmo executor Python e salvam log e JSON em `relatorios-testes`.
Os testes continuam sendo os da suite existente; nenhum resultado é presumido.

## Verificações diretas no Windows

| Caso executado | Resultado observado |
| --- | --- |
| Atalho `testar.cmd`, PCAP real e TShark presentes | 21 aprovados, nenhum ignorado, saída 0 |
| Caminho informado inexistente | Mensagem de erro, saída 2, sem iniciar testes |
| Executor fora da pasta do projeto e perfil temporário sem PCAP | 18 aprovados, 3 ignorados, saída 0 e resultado incompleto explícito |
| Arquivo inválido passado ao atalho | 18 aprovados; erro na preparação dos testes reais; saída 1 |

Os cenários sem PCAP e com arquivo inválido foram verificações controladas do
executor. Não representam falhas do experimento real. Cada execução criou sua
própria pasta de resultados, sem sobrescrever as anteriores.

## Execução no Raspberry Pi

Em 18/11/2026, o usuário executou `testar.sh` com Python 3.13.5 no Raspberry Pi.
Pela saída compartilhada, o script encontrou o PCAP automaticamente, rodou
21 testes em 0,525 s e salvou o log e o JSON em `relatorios-testes`.
Foram **20 aprovados, 1 ignorado, 0 falhas e 0 erros**. Os dois testes do PCAP
real passaram, incluindo a conferência do SHA-256 e das portas 22 e 23.
A comparação independente foi ignorada porque o TShark estava indisponível
no Raspberry. Essa comparação passou na execução do Windows.

## Arquivos gerados

Os atalhos não geram os relatórios completos do experimento. Eles executam a
suite, incluindo os testes de exportação em arquivos temporários, e conservam
somente os resultados dos testes. Para analisar o PCAP e gerar seus relatórios,
consulte a Etapa 1 do [guia](inicio-rapido.md).
