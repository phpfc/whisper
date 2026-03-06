# Homebrew Formula for t-chat
#
# Installation via tap:
#   brew tap phpfc/t-chat https://github.com/phpfc/t-chat
#   brew install t-chat
#
# Or directly:
#   brew install phpfc/t-chat/t-chat

class TChat < Formula
  desc "Secure P2P chat in the terminal. Zero config, no servers needed"
  homepage "https://github.com/phpfc/t-chat"
  url "https://github.com/phpfc/t-chat/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "PLACEHOLDER_SHA256"
  license "MIT"
  head "https://github.com/phpfc/t-chat.git", branch: "main"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args
  end

  test do
    assert_match "t-chat", shell_output("#{bin}/t-chat --version")
  end
end
