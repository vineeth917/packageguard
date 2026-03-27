#!/bin/bash
# PackageGuard — Quick Start for Hackathon
# Run this first to set up the project

set -e

echo "🛡️ PackageGuard — Setting up..."

# Create .env file if not exists
if [ ! -f .env ]; then
    cat > .env << 'EOF'
ANTHROPIC_API_KEY=your-key-here
OVERMIND_API_KEY=your-key-here
AEROSPIKE_HOST=localhost
AEROSPIKE_PORT=3000
EOF
    echo "⚠️  Created .env file — fill in your API keys!"
fi

# Install dependencies
echo "📦 Installing Python dependencies..."
pip install anthropic httpx click rich fastapi uvicorn pyyaml docker 2>/dev/null || true

# Try to install optional deps
pip install guarddog aerospike 2>/dev/null || echo "⚠️  Some optional deps not available (guarddog, aerospike)"

echo ""
echo "✅ Setup complete!"
echo ""
echo "📋 Next steps:"
echo "  1. Fill in .env with your API keys"
echo "  2. Claude Code: work on agents/ and scanners/ (see docs/claude.md)"
echo "  3. Codex: work on resolver/, cache/, api/ (see docs/codex.md)"
echo ""
echo "🚀 To run:"
echo "  python -m packageguard scan <package>==<version>"
echo "  uvicorn packageguard.api.server:app --reload"
echo ""
echo "🐳 To run with Docker:"
echo "  docker-compose up --build"
