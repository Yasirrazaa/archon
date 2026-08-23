# Homebrew formula for the Archon security CLI.
#
# Install (after tapping this repo or using the raw formula URL):
#   brew install --build-from-source ./packaging/homebrew/archon.rb
#   archon plugins --ci
class Archon < Formula
  desc "Closed-loop agent security: red team + blue team in one MIT tool"
  homepage "https://github.com/Yasirrazaa/archon"
  url "https://github.com/Yasirrazaa/archon/archive/refs/heads/hackathon-v2.tar.gz"
  version "0.1.0"
  license "MIT"

  depends_on "uv"

  def install
    # uv-managed virtualenv keeps the install hermetic and reproducible.
    system "uv", "sync", "--frozen"
    venv = Libexec/"venv"
    system "uv", "pip", "install", "--python", ".venv/bin/python", ".", "--target", venv
    binary = "archon"
    bin.install_symlink venv/"bin"/binary
  end

  test do
    # Inventory command exercises imports, probe packs, and exit codes.
    system "#{bin}/archon", "plugins", "--ci"
  end
end
