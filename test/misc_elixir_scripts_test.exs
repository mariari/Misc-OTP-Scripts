defmodule MiscElixirScriptsTest do
  use ExUnit.Case
  doctest MiscElixirScripts

  test "greets the world" do

    assert MiscElixirScripts.hello() == :world

    assert Misc.First.fact(5) == 120

  end
end
