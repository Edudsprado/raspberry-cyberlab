# GitHub — Raspberry CyberLab

Repositório do projeto:
**https://github.com/Edudsprado/raspberry-cyberlab**

Criado em 17/11/2026 na conta `Edudsprado`, inicialmente **privado**. A branch
principal é `main`. Enquanto privado, o professor precisará de uma conta autorizada
para consultar o código. A visibilidade pode ser alterada no GitHub após a revisão.

## Conteúdo enviado

- Código Python do analisador e testes automatizados.
- README com execução no Windows/Kali, metodologia, relatório forense e roteiro acadêmico.
- Seleção textual das evidências reais e log da validação.

O `.gitignore` exclui capturas, relatórios completos, ambientes virtuais e arquivos
temporários. `docs/evidencias` contém a seleção de evidências de loopback usada nas
conclusões escritas. O PCAP original permanece somente na máquina do usuário.

## Baixar em outra máquina

Com Git e Python 3.10+ instalados:

```bash
git clone https://github.com/Edudsprado/raspberry-cyberlab.git
cd raspberry-cyberlab
python -m unittest discover -v
```

No Kali/Raspberry, use `python3` no lugar de `python`. O acesso ao repositório
privado requer autenticação na conta autorizada. O PCAP não será baixado pelo Git;
copie a evidência separadamente e confira seu SHA-256.

## Enviar futuras alterações

O primeiro envio foi feito pela página do GitHub. Para continuar com o Git,
use a cópia obtida pelo `git clone` acima: ela já contém o histórico remoto.
A pasta original de desenvolvimento conserva um commit local de preparação
com histórico independente; não execute um push dessa cópia sem sincronizá-la.

Na pasta clonada, revise os arquivos e execute:

```powershell
python -m unittest discover -v
git status --short
git add README.md cyberlab tests docs
git diff --cached --stat
git diff --cached
git commit -m "Descreva a alteracao realizada"
git push
```

Se modificar outros arquivos, acrescente seus nomes ao `git add`. Configure a
autoria na cópia clonada antes de criar novos commits. Na pasta original,
o commit de preparação usa `Edudsprado` e um endereço noreply, sem alterar
a configuração global do Git. Os commits enviados pelo navegador usam a
autoria configurada na conta do GitHub.

Autentique pela janela do Git/GitHub quando solicitada; não coloque tokens ou
senhas no código, na URL ou na documentação. Ainda não foi escolhida uma licença;
decida os termos de reutilização antes de abrir o código publicamente.
