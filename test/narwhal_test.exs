defmodule MiscTest.Narwhal do

  use ExUnit.Case, async: true

  import Misc.Narwhal.Validator
  import Misc.Narwhal.Primary

  doctest Misc

  test "Signing works on round 0" do
    {:ok, pid} = Misc.Narwhal.Validator.start_link(3)

    p_pid = Misc.Narwhal.Validator.get_primary(pid)

    {pub, priv} = :crypto.generate_key(:rsa, {1024,65537})

    block = %{block: %{transactions: nil, certificates: nil}, round: 0, pub_key: pub}

    signed = create_signature(block, priv)

    signed_block = {block, create_signature(block, priv)}

    assert sign_block(p_pid, signed_block) != :error


  end



end
