# Homebrew Formula for t-chat
# To use this formula:
# 1. Create a GitHub release with a tarball of the source
# 2. Update the url and sha256 below
# 3. Either submit to homebrew-core or create your own tap

class TChat < Formula
  desc "Simple, secure, and private P2P chat CLI with E2E encryption"
  homepage "https://github.com/phpfc/t-chat"
  url "https://github.com/phpfc/t-chat/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "PLACEHOLDER_SHA256"
  license "MIT"
  head "https://github.com/phpfc/t-chat.git", branch: "master"

  bottle do
    root_url "https://github.com/phpfc/t-chat/releases/download/v0.1.0"
    rebuild 0
    sha256 cellar: :any_skip_relocation, arm64_tahoe: "PLACEHOLDER_SHA256"
  end

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args
  end

  test do
    system "#{bin}/t-chat", "--version"
    assert_match "t-chat", shell_output("#{bin}/t-chat --version 2>&1")
  end
end
