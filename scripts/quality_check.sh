#!/bin/bash
# Script para executar todos os testes e verificações de qualidade
# Etapa 7: Testes e Qualidade

set -e

echo "🚀 Iniciando verificações de qualidade de código..."
echo "=============================================="

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Função para imprimir status
print_status() {
    echo -e "${BLUE}📋 $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# 1. Verificar formatação do código
print_status "Verificando formatação do código..."
if cargo fmt --all -- --check; then
    print_success "Formatação do código está correta"
else
    print_error "Código não está formatado corretamente"
    echo "Execute: cargo fmt --all"
    exit 1
fi

echo ""

# 2. Executar Clippy (linting)
print_status "Executando Clippy (análise estática)..."
if cargo clippy --all-targets --all-features -- -D warnings; then
    print_success "Clippy passou sem warnings"
else
    print_error "Clippy encontrou problemas"
    exit 1
fi

echo ""

# 3. Verificar compilação
print_status "Verificando compilação..."
if cargo check --all-targets --all-features; then
    print_success "Código compila sem erros"
else
    print_error "Erro de compilação"
    exit 1
fi

echo ""

# 4. Executar testes unitários
print_status "Executando testes unitários..."
if cargo test --lib --all-features --verbose; then
    print_success "Testes unitários passaram"
else
    print_error "Testes unitários falharam"
    exit 1
fi

echo ""

# 5. Executar testes de integração
print_status "Executando testes de integração..."
if cargo test --test '*' --all-features --verbose; then
    print_success "Testes de integração passaram"
else
    print_error "Testes de integração falharam"
    exit 1
fi

echo ""

# 6. Executar todos os testes
print_status "Executando todos os testes..."
if cargo test --all-features --verbose; then
    print_success "Todos os testes passaram"
else
    print_error "Alguns testes falharam"
    exit 1
fi

echo ""

# 7. Verificar dependências vulneráveis (se cargo-audit estiver instalado)
if command -v cargo-audit &> /dev/null; then
    print_status "Verificando vulnerabilidades de segurança..."
    if cargo audit; then
        print_success "Nenhuma vulnerabilidade encontrada"
    else
        print_warning "Vulnerabilidades encontradas - verifique o relatório acima"
    fi
else
    print_warning "cargo-audit não está instalado. Instale com: cargo install cargo-audit"
fi

echo ""

# 8. Verificar dependências desatualizadas (se cargo-outdated estiver instalado)
if command -v cargo-outdated &> /dev/null; then
    print_status "Verificando dependências desatualizadas..."
    cargo outdated
else
    print_warning "cargo-outdated não está instalado. Instale com: cargo install cargo-outdated"
fi

echo ""

# 9. Build de release
print_status "Testando build de release..."
if cargo build --release --all-features; then
    print_success "Build de release concluído"
else
    print_error "Erro no build de release"
    exit 1
fi

echo ""

# 10. Executar testes com coverage (se tarpaulin estiver instalado)
if command -v cargo-tarpaulin &> /dev/null; then
    print_status "Executando testes com coverage..."
    if cargo tarpaulin --verbose --all-features --workspace --timeout 120; then
        print_success "Coverage gerado com sucesso"
    else
        print_warning "Erro ao gerar coverage"
    fi
else
    print_warning "cargo-tarpaulin não está instalado. Instale com: cargo install cargo-tarpaulin"
fi

echo ""

# Resumo final
echo "=============================================="
print_success "🎉 Todas as verificações passaram com sucesso!"
echo ""
echo "Verificações realizadas:"
echo "- ✅ Formatação de código"
echo "- ✅ Análise estática (Clippy)"
echo "- ✅ Compilação"
echo "- ✅ Testes unitários"
echo "- ✅ Testes de integração"
echo "- ✅ Build de release"
echo "- ⚡ Auditoria de segurança (se disponível)"
echo "- 📊 Coverage de testes (se disponível)"
echo ""
print_success "Código pronto para produção! 🚀"
