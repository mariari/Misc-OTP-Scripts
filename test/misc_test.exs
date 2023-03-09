defmodule MiscTest do
  use ExUnit.Case, async: true
  doctest Misc

  test "greets the world" do
    assert Misc.hello() == :world
  end

  test "Factorial check" do
    assert Misc.First.fact(5) == 120
    assert Misc.First.fact(5) == Misc.First.fact_proper(5)
  end
end
