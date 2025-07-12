# Script PowerShell para verificações de qualidade de código
# Etapa 7: Testes e Qualidade

param(
    [switch]$SkipTests,
    [switch]$SkipLint,
    [switch]$QuickCheck
)

# Configurações
$ErrorActionPreference = "Stop"

# Cores para output
function Write-Status {
    param($Message)
    Write-Host "📋 $Message" -ForegroundColor Blue
}

function Write-Success {
    param($Message)
    Write-Host "✅ $Message" -ForegroundColor Green
}

function Write-Warning {
    param($Message)
    Write-Host "⚠️  $Message" -ForegroundColor Yellow
}

function Write-Error-Custom {
    param($Message)
    Write-Host "❌ $Message" -ForegroundColor Red
}

function Test-Command {
    param($Command)
    try {
        Get-Command $Command -ErrorAction Stop | Out-Null
        return $true
    }
    catch {
        return $false
    }
}

Write-Host "🚀 Iniciando verificações de qualidade de código..." -ForegroundColor Cyan
Write-Host "==============================================`n" -ForegroundColor Cyan

$totalErrors = 0

# 1. Verificar formatação do código
if (-not $SkipLint) {
    Write-Status "Verificando formatação do código..."
    try {
        cargo fmt --all -- --check
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Formatação do código está correta"
        } else {
            Write-Error-Custom "Código não está formatado corretamente"
            Write-Host "Execute: cargo fmt --all" -ForegroundColor Yellow
            $totalErrors++
        }
    }
    catch {
        Write-Error-Custom "Erro ao verificar formatação: $_"
        $totalErrors++
    }
    Write-Host ""
}

# 2. Executar Clippy (linting)
if (-not $SkipLint) {
    Write-Status "Executando Clippy (análise estática)..."
    try {
        cargo clippy --all-targets --all-features -- -D warnings
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Clippy passou sem warnings"
        } else {
            Write-Error-Custom "Clippy encontrou problemas"
            $totalErrors++
        }
    }
    catch {
        Write-Error-Custom "Erro ao executar Clippy: $_"
        $totalErrors++
    }
    Write-Host ""
}

# 3. Verificar compilação
Write-Status "Verificando compilação..."
try {
    cargo check --all-targets --all-features
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Código compila sem erros"
    } else {
        Write-Error-Custom "Erro de compilação"
        $totalErrors++
    }
}
catch {
    Write-Error-Custom "Erro ao verificar compilação: $_"
    $totalErrors++
}
Write-Host ""

# 4. Executar testes (se não for quick check)
if (-not $SkipTests -and -not $QuickCheck) {
    Write-Status "Executando testes unitários..."
    try {
        cargo test --lib --all-features --verbose
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Testes unitários passaram"
        } else {
            Write-Error-Custom "Testes unitários falharam"
            $totalErrors++
        }
    }
    catch {
        Write-Error-Custom "Erro ao executar testes unitários: $_"
        $totalErrors++
    }
    Write-Host ""

    Write-Status "Executando testes de integração..."
    try {
        cargo test --test '*' --all-features --verbose
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Testes de integração passaram"
        } else {
            Write-Error-Custom "Testes de integração falharam"
            $totalErrors++
        }
    }
    catch {
        Write-Error-Custom "Erro ao executar testes de integração: $_"
        $totalErrors++
    }
    Write-Host ""
}

# 5. Build de release
if (-not $QuickCheck) {
    Write-Status "Testando build de release..."
    try {
        cargo build --release --all-features
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Build de release concluído"
        } else {
            Write-Error-Custom "Erro no build de release"
            $totalErrors++
        }
    }
    catch {
        Write-Error-Custom "Erro ao fazer build de release: $_"
        $totalErrors++
    }
    Write-Host ""
}

# 6. Verificar cargo-audit se disponível
if (Test-Command "cargo-audit") {
    Write-Status "Verificando vulnerabilidades de segurança..."
    try {
        cargo audit
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Nenhuma vulnerabilidade encontrada"
        } else {
            Write-Warning "Vulnerabilidades encontradas - verifique o relatório acima"
        }
    }
    catch {
        Write-Warning "Erro ao executar auditoria de segurança: $_"
    }
} else {
    Write-Warning "cargo-audit não está instalado. Instale com: cargo install cargo-audit"
}
Write-Host ""

# 7. Verificar dependências desatualizadas
if (Test-Command "cargo-outdated") {
    Write-Status "Verificando dependências desatualizadas..."
    try {
        cargo outdated
    }
    catch {
        Write-Warning "Erro ao verificar dependências: $_"
    }
} else {
    Write-Warning "cargo-outdated não está instalado. Instale com: cargo install cargo-outdated"
}
Write-Host ""

# Resumo final
Write-Host "==============================================`n" -ForegroundColor Cyan

if ($totalErrors -eq 0) {
    Write-Success "🎉 Todas as verificações passaram com sucesso!"
    Write-Host ""
    Write-Host "Verificações realizadas:" -ForegroundColor Cyan
    if (-not $SkipLint) {
        Write-Host "- ✅ Formatação de código" -ForegroundColor Green
        Write-Host "- ✅ Análise estática (Clippy)" -ForegroundColor Green
    }
    Write-Host "- ✅ Compilação" -ForegroundColor Green
    
    if (-not $SkipTests -and -not $QuickCheck) {
        Write-Host "- ✅ Testes unitários" -ForegroundColor Green
        Write-Host "- ✅ Testes de integração" -ForegroundColor Green
    }
    
    if (-not $QuickCheck) {
        Write-Host "- ✅ Build de release" -ForegroundColor Green
    }
    
    Write-Host "- ⚡ Auditoria de segurança (se disponível)" -ForegroundColor Yellow
    Write-Host ""
    Write-Success "Código pronto para produção! 🚀"
} else {
    Write-Error-Custom "❌ $totalErrors erro(s) encontrado(s)"
    Write-Host "Por favor, corrija os problemas antes de continuar." -ForegroundColor Red
    exit 1
}

# Informações adicionais
Write-Host "`nComandos úteis:" -ForegroundColor Cyan
Write-Host "- .\scripts\quality_check.ps1 -QuickCheck    # Verificação rápida" -ForegroundColor Yellow
Write-Host "- .\scripts\quality_check.ps1 -SkipTests     # Pular testes" -ForegroundColor Yellow
Write-Host "- .\scripts\quality_check.ps1 -SkipLint      # Pular linting" -ForegroundColor Yellow
Write-Host "- cargo fmt --all                            # Formatar código" -ForegroundColor Yellow
Write-Host "- cargo clippy --fix                         # Corrigir problemas do Clippy" -ForegroundColor Yellow
