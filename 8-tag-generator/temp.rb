require 'zip'

TMP_FOLDER = '/tmp'
FINAL_FOLDER = '/tmp'

filename = 'images.zip'

Zip::File.open(filename) do |zip_file|

  # handle each entry one by one
  zip_file.each do |entry|

    out_file = "#{ TMP_FOLDER }/#{ entry.name }"

    entry.extract(out_file){
      true
    }
  end
end
