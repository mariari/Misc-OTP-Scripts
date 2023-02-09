defmodule MiscElixirScriptsTest do
  use ExUnit.Case
  doctest MiscElixirScripts

  test "greets the world" do

    assert MiscElixirScripts.hello() == :world

  end

  test "Factorial check" do
    assert Misc.First.fact(5) == 120
    assert Misc.First.fact(5) == Misc.First.fact_proper(5)
  end
end
