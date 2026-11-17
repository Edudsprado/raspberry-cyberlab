# Roteiro de entrega — 24/11/2026

Plano sugerido, sem presumir que as etapas futuras já foram concluídas:

| Data | Etapa e resultado esperado |
| --- | --- |
| 17/11 | Primeira versão criada e testada no PCAP real no Windows; revisar os arquivos produzidos |
| 18/11 | Executar pessoalmente os comandos do README e conferir portas 22/23 no Wireshark |
| 19/11 | Testar no Kali ou Raspberry; registrar versões e corrigir diferenças, se houver |
| 20/11 | Recuperar comando Nmap, comando de captura, interface e contexto original; completar método experimental |
| 21/11 | Revisar autoria e evidências; escolher licença/visibilidade; publicar no GitHub |
| 22/11 | Preparar relatório e apresentação: problema, método, demonstração e limites |
| 23/11 | Ensaiar demonstração; guardar cópia offline do código, PCAP original e relatórios |
| 24/11 | Entrega acadêmica e apresentação |

## Pendências de evidência

- Registrar os comandos originais do Nmap e tcpdump; não reconstruí-los de memória como fatos.
- Registrar modelo do Raspberry, versão do sistema e interface de captura a partir de fonte verificável.
- Anexar imagens originais do Wireshark, se exigidas pela instituição.
- Confirmar formato do trabalho, autoria, referências e exigências do professor.

## Demonstração curta

1. Apresentar a pergunta: como distinguir os padrões TCP de uma porta aberta e uma fechada?
2. Identificar o PCAP e conferir SHA-256.
3. Executar `python -m cyberlab` sobre a evidência local.
4. Mostrar o resumo CSV das portas 22/23 e os pacotes correspondentes no JSON/Wireshark.
5. Explicar por que ausência de resposta não prova porta fechada e por que o hash não prova origem.
6. Apresentar os testes e as limitações da primeira versão.
