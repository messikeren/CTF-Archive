println("========= JULIA CODE EDITOR =========")
println("Welcome, please enter your code to be executed")
println("Note: end the code with --END\n")

code = "" :: String

function checker(line :: String)
  blacklist = ["rm", "open", "read", "readdir", "Base", "run", "Pkg", "using", "pyimport"] :: Array{String, 1}
  for word in blacklist
    if occursin(word, line)
      return false
    end
  end
  return true
end

println("---------------- START ----------------\n")
index = 1 :: Int
while true
  print("$index ")
  line = readline() :: String
  if line == "--END"
    break
  end
  global code *= line * "\n"
  global index += 1
end
println("\n---------------- END ----------------")

println("\n[+] Checking the code...")
if checker(code)
  println("[i] Code is safe, execute the code...\n")
else
  println("[x] Dangerous word is detected, exiting...\n")
  exit()
end

filecode = "code.jl" :: String
open(filecode, "w") do f
  write(f, code)
end

try
  println("---------------- OUTPUT ----------------\n")
  include(filecode)
catch e
  println("Error: $e")
finally
  println("\n---------------- END OUTPUT ----------------")
  rm(filecode)
end

println("\nThank you for using Julia Code Editor, love from @rootkids 😚")
