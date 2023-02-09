defmodule MiscElixirScriptsTest do
  use ExUnit.Case
  doctest MiscElixirScripts

  test "greets the world" do

    assert MiscElixirScripts.hello() == :world
  end
end
