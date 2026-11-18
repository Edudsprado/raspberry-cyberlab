# Roteiro de entrega — 24/11/2026

Plano sugerido, sem presumir que as etapas futuras já foram concluídas:

| Data | Etapa e resultado esperado |
| --- | --- |
| 17/11 | Primeira versão criada e testada no PCAP real no Windows; revisar os arquivos produzidos |
| 18/11 | Retomada validada no Windows: 21 testes aprovados e relatórios conferidos; próximo passo do usuário é reproduzir o guia curto |
| 19/11 | Conferir portas 22/23 e revisar os registros existentes do Raspberry; Kali é opcional e não foi validado |
| 20/11 | Completar o método com fontes disponíveis; comandos originais e interface permanecem não recuperados nos registros existentes |
| 21/11 | Revisar autoria e evidências; preparar a entrega do código; eventual publicação exige revisão do conteúdo e decisão de visibilidade |
| 22/11 | Preparar relatório e apresentação: problema, método, demonstração e limites |
| 23/11 | Ensaiar demonstração; guardar cópia offline do código, PCAP original e relatórios |
| 24/11 | Entrega acadêmica e apresentação |

## Pendências de evidência

- Registrar os comandos originais do Nmap e tcpdump; não reconstruí-los de memória como fatos.
- Revisar as transcrições já registradas de modelo e sistema do Raspberry; a interface original de captura permanece não identificada.
- Anexar imagens originais do Wireshark, se exigidas pela instituição.
- Confirmar formato do trabalho, autoria, referências e exigências do professor.

## Demonstração curta

1. Apresentar a pergunta: como distinguir os padrões TCP de uma porta aberta e uma fechada?
2. Identificar o PCAP e conferir SHA-256.
3. Executar `python -m cyberlab` sobre a evidência local.
4. Mostrar o resumo CSV das portas 22/23 e os pacotes correspondentes no JSON/Wireshark.
5. Explicar por que ausência de resposta não prova porta fechada e por que o hash não prova origem.
6. Apresentar os testes e as limitações da primeira versão.
