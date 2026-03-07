# Homebrew Formula for Whisper
# Install via: brew tap phpfc/whisper && brew install whisper

class Whisper < Formula
  desc "Secure P2P chat in the terminal. Zero config, no servers needed"
  homepage "https://github.com/phpfc/whisper"
  url "https://github.com/phpfc/whisper/archive/refs/tags/v0.2.1.tar.gz"
  sha256 "de61701fde38fe33b160e024f7a44ffa962892365c82134316a0fe4b5a6fb676"
  license "MIT"
  head "https://github.com/phpfc/whisper.git", branch: "main"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args
  end

  test do
    assert_match "whisper 0.2.1", shell_output("#{bin}/whisper --version")
  end
end
