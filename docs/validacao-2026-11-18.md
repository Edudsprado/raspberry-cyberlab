# Validação da retomada — 18/11/2026

A versão 0.1.0 já existente foi revisada e executada diretamente nesta máquina
Windows, com Python 3.12.3. O código do analisador foi preservado. Os registros
anteriores e as alterações locais existentes também foram conservados.

## Verificações executadas

- 21 testes aprovados, sem falhas, erros ou casos ignorados: 18 testes sintéticos
  e 3 sobre o PCAP real, incluindo comparação de evidências e fluxos com TShark.
- Execução de `python -m cyberlab` com conferência obrigatória do SHA-256.
- JSON carregado novamente e três CSVs lidos para verificar quantidade de linhas.
- SHA-256 calculado separadamente antes e depois: iguais ao hash esperado.

O [log integral dos testes](evidencias/unittest-windows-2026-11-18.txt) e o
[registro estruturado](evidencias/validacao-2026-11-18.json) foram produzidos
pela execução desta retomada. O registro inclui hashes dos arquivos Python
analisados e dos quatro relatórios gerados.

## Resultados medidos

| Medida | Resultado |
| --- | --- |
| Entrada | `experimento-nmap.pcap`, em Downloads |
| Tamanho | 160.208 bytes |
| Pacotes / TCP / ignorados | 2.002 / 2.002 / 0 |
| Fluxos direcionais | 2.000 |
| Tentativas | 1 aberta, 999 fechadas |
| Linhas em portas.csv / tentativas.csv / fluxos-tcp.csv | 1.000 / 1.000 / 2.000 |
| Porta 22 | Aberta; pacotes 19, 20 e 21 |
| Porta 23 | Fechada; pacotes 31 e 32 |
| Flags por combinação | SYN: 1.000; SYN/ACK: 1; ACK: 1; RST/ACK: 1.000 |

SHA-256 antes e depois:

```text
ddd44c144ea60620c3fcf4a1e2ef9c7e53ed643b291642f11c896322f6c59a8e
```

Os quatro relatórios conferidos estão em `relatorios-retomada-2026-11-18-02`,
fora do controle de versão. A primeira pasta, `relatorios-retomada-2026-11-18`,
foi gerada antes de um erro de codificação no coletor auxiliar de validação.
O coletor foi corrigido e a verificação foi repetida por completo na pasta `-02`;
os logs e números acima correspondem à execução concluída com sucesso.

## Limites desta confirmação

Não houve nova captura, varredura, conexão SSH ou execução no Raspberry/Kali.
Os registros remotos anteriores permanecem identificados nas outras páginas
como transcrições fornecidas pelo usuário. Nada foi publicado nesta retomada.
O pacote de entrega não inclui PCAPs nem relatórios completos; as evidências
resumidas desta verificação referem-se aos endpoints loopback do experimento.

Os testes cobrem os casos implementados e não demonstram ausência de bugs.
A classificação exige o handshake completo para `aberta`; SYN/ACK isolado
permanece inconclusivo. Capturas parciais e formatos fora do escopo continuam
sujeitos às limitações descritas no [guia](inicio-rapido.md).
